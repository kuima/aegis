/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2020  The Trojan Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "serversession.h"
#include "proto/trojanrequest.h"
#include "proto/udppacket.h"
#include <cctype>
using namespace std;
using namespace boost::asio::ip;
using namespace boost::asio::ssl;

namespace {
constexpr int TLS_HANDSHAKE_TIMEOUT = 10;
constexpr int TROJAN_REQUEST_TIMEOUT = 10;
constexpr int OUTBOUND_CONNECT_TIMEOUT = 30;

bool is_hex_prefix(const string &data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        if (!isxdigit(static_cast<unsigned char>(data[i]))) {
            return false;
        }
    }
    return true;
}
}

ServerSession::ServerSession(const Config &config, boost::asio::io_context &io_context, context &ssl_context, Authenticator *auth, const string &plain_http_response) :
    Session(config, io_context),
    status(HANDSHAKE),
    in_socket(io_context, ssl_context),
    out_socket(io_context),
    udp_resolver(io_context),
    operation_timer(io_context),
    auth(auth),
    plain_http_response(plain_http_response) {}

tcp::socket& ServerSession::accept_socket() {
    return (tcp::socket&)in_socket.next_layer();
}

void ServerSession::start() {
    boost::system::error_code ec;
    start_time = time(nullptr);
    in_endpoint = in_socket.next_layer().remote_endpoint(ec);
    if (ec) {
        destroy();
        return;
    }
    auto self = shared_from_this();
    arm_timer(TLS_HANDSHAKE_TIMEOUT, "TLS handshake timed out");
    in_socket.async_handshake(stream_base::server, [this, self](const boost::system::error_code error) {
        if (error) {
            cancel_timer();
            Log::log_with_endpoint(in_endpoint, "SSL handshake failed: " + error.message(), Log::ERROR);
            if (error.message() == "http request" && !plain_http_response.empty()) {
                recv_len += plain_http_response.length();
                boost::asio::async_write(accept_socket(), boost::asio::buffer(plain_http_response), [this, self](const boost::system::error_code, size_t) {
                    destroy();
                });
                return;
            }
            destroy();
            return;
        }
        arm_timer(TROJAN_REQUEST_TIMEOUT, "Trojan request timed out");
        in_async_read();
    });
}

void ServerSession::arm_timer(int seconds, const string &message) {
    operation_timer.expires_after(chrono::seconds(seconds));
    auto self = shared_from_this();
    operation_timer.async_wait([this, self, message](const boost::system::error_code error) {
        if (error == boost::asio::error::operation_aborted || status == DESTROY) {
            return;
        }
        Log::log_with_endpoint(in_endpoint, message, Log::WARN);
        destroy();
    });
}

void ServerSession::cancel_timer() {
    operation_timer.cancel();
}

ServerSession::RequestState ServerSession::inspect_trojan_request(const string &data, TrojanRequest &req) {
    constexpr size_t PASSWORD_LENGTH = 56;
    constexpr size_t PASSWORD_CRLF_LENGTH = PASSWORD_LENGTH + 2;

    if (data.size() < PASSWORD_LENGTH) {
        return is_hex_prefix(data, data.size()) ? REQUEST_INCOMPLETE : REQUEST_INVALID;
    }
    if (!is_hex_prefix(data, PASSWORD_LENGTH)) {
        return REQUEST_INVALID;
    }
    if (data.size() == PASSWORD_LENGTH) {
        return REQUEST_INCOMPLETE;
    }
    if (data[PASSWORD_LENGTH] != '\r') {
        return REQUEST_INVALID;
    }
    if (data.size() == PASSWORD_LENGTH + 1) {
        return REQUEST_INCOMPLETE;
    }
    if (data[PASSWORD_LENGTH + 1] != '\n') {
        return REQUEST_INVALID;
    }
    if (data.size() == PASSWORD_CRLF_LENGTH) {
        return REQUEST_INCOMPLETE;
    }
    unsigned char command = data[PASSWORD_CRLF_LENGTH];
    if (command != TrojanRequest::CONNECT && command != TrojanRequest::UDP_ASSOCIATE) {
        return REQUEST_INVALID;
    }
    if (data.size() == PASSWORD_CRLF_LENGTH + 1) {
        return REQUEST_INCOMPLETE;
    }

    size_t address_len = 0;
    unsigned char address_type = data[PASSWORD_CRLF_LENGTH + 1];
    switch (address_type) {
        case SOCKS5Address::IPv4:
            address_len = 1 + 4 + 2;
            break;
        case SOCKS5Address::DOMAINNAME: {
            if (data.size() == PASSWORD_CRLF_LENGTH + 2) {
                return REQUEST_INCOMPLETE;
            }
            unsigned char domain_len = data[PASSWORD_CRLF_LENGTH + 2];
            if (domain_len == 0) {
                return REQUEST_INVALID;
            }
            address_len = 1 + 1 + domain_len + 2;
            break;
        }
        case SOCKS5Address::IPv6:
            address_len = 1 + 16 + 2;
            break;
        default:
            return REQUEST_INVALID;
    }

    size_t request_crlf = PASSWORD_CRLF_LENGTH + 1 + address_len;
    if (data.size() < request_crlf + 2) {
        return REQUEST_INCOMPLETE;
    }
    if (data.compare(request_crlf, 2, "\r\n") != 0) {
        return REQUEST_INVALID;
    }
    return req.parse(data) == -1 ? REQUEST_INVALID : REQUEST_COMPLETE;
}

void ServerSession::in_async_read() {
    auto self = shared_from_this();
    in_socket.async_read_some(boost::asio::buffer(in_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        in_recv(string((const char*)in_read_buf, length));
    });
}

void ServerSession::in_async_write(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(in_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        in_sent();
    });
}

void ServerSession::out_async_read() {
    auto self = shared_from_this();
    out_socket.async_read_some(boost::asio::buffer(out_read_buf, MAX_LENGTH), [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        out_recv(string((const char*)out_read_buf, length));
    });
}

void ServerSession::out_async_write(const string &data) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    boost::asio::async_write(out_socket, boost::asio::buffer(*data_copy), [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        out_sent();
    });
}

void ServerSession::udp_async_read() {
    auto self = shared_from_this();
    udp_socket.async_receive_from(boost::asio::buffer(udp_read_buf, MAX_LENGTH), udp_recv_endpoint, [this, self](const boost::system::error_code error, size_t length) {
        if (error) {
            destroy();
            return;
        }
        udp_recv(string((const char*)udp_read_buf, length), udp_recv_endpoint);
    });
}

void ServerSession::udp_async_write(const string &data, const udp::endpoint &endpoint) {
    auto self = shared_from_this();
    auto data_copy = make_shared<string>(data);
    udp_socket.async_send_to(boost::asio::buffer(*data_copy), endpoint, [this, self, data_copy](const boost::system::error_code error, size_t) {
        if (error) {
            destroy();
            return;
        }
        udp_sent();
    });
}

void ServerSession::in_recv(const string &data) {
    if (status == HANDSHAKE) {
        handshake_buf += data;
        TrojanRequest req;
        RequestState request_state = inspect_trojan_request(handshake_buf, req);
        if (request_state == REQUEST_INCOMPLETE) {
            if (handshake_buf.length() > MAX_LENGTH) {
                Log::log_with_endpoint(in_endpoint, "Trojan request header too long", Log::ERROR);
                destroy();
                return;
            }
            in_async_read();
            return;
        }
        cancel_timer();
        bool valid = request_state == REQUEST_COMPLETE;
        if (valid) {
            auto password_iterator = config.password.find(req.password);
            if (password_iterator == config.password.end()) {
                valid = false;
                if (auth && auth->auth(req.password)) {
                    valid = true;
                    auth_password = req.password;
                    Log::log_with_endpoint(in_endpoint, "authenticated by authenticator (" + req.password.substr(0, 7) + ')', Log::INFO);
                }
            } else {
                Log::log_with_endpoint(in_endpoint, "authenticated as " + password_iterator->second, Log::INFO);
            }
            if (!valid) {
                Log::log_with_endpoint(in_endpoint, "valid trojan request structure but possibly incorrect password (" + req.password + ')', Log::WARN);
            }
        }
        string query_addr = valid ? req.address.address : config.remote_addr;
        string query_port = to_string([&]() {
            if (valid) {
                return req.address.port;
            }
            const unsigned char *alpn_out;
            unsigned int alpn_len;
            SSL_get0_alpn_selected(in_socket.native_handle(), &alpn_out, &alpn_len);
            if (alpn_out == nullptr) {
                return config.remote_port;
            }
            auto it = config.ssl.alpn_port_override.find(string(alpn_out, alpn_out + alpn_len));
            return it == config.ssl.alpn_port_override.end() ? config.remote_port : it->second;
        }());
        if (valid) {
            out_write_buf = req.payload;
            if (req.command == TrojanRequest::UDP_ASSOCIATE) {
                Log::log_with_endpoint(in_endpoint, "requested UDP associate to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
                status = UDP_FORWARD;
                udp_data_buf = out_write_buf;
                udp_sent();
                return;
            } else {
                Log::log_with_endpoint(in_endpoint, "requested connection to " + req.address.address + ':' + to_string(req.address.port), Log::INFO);
            }
        } else {
            Log::log_with_endpoint(in_endpoint, "not trojan request, connecting to " + query_addr + ':' + query_port, Log::WARN);
            out_write_buf = handshake_buf;
        }
        sent_len += out_write_buf.length();
        auto self = shared_from_this();
        arm_timer(OUTBOUND_CONNECT_TIMEOUT, "outbound connection timed out");
        resolver.async_resolve(query_addr, query_port, [this, self, query_addr, query_port](const boost::system::error_code error, const tcp::resolver::results_type& results) {
            if (status == DESTROY) {
                return;
            }
            if (error || results.empty()) {
                cancel_timer();
                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + query_addr + ": " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            auto endpoints = make_shared<vector<tcp::endpoint> >();
            if (!config.tcp.prefer_ipv4) {
                for (const auto &result: results) {
                    endpoints->push_back(result.endpoint());
                }
            } else {
                for (const auto &result: results) {
                    if (result.endpoint().address().is_v4()) {
                        endpoints->push_back(result.endpoint());
                    }
                }
                for (const auto &result: results) {
                    if (!result.endpoint().address().is_v4()) {
                        endpoints->push_back(result.endpoint());
                    }
                }
            }
            start_outbound_connect(endpoints, 0, query_addr, query_port);
        });
    } else if (status == FORWARD) {
        sent_len += data.length();
        out_async_write(data);
    } else if (status == UDP_FORWARD) {
        udp_data_buf += data;
        udp_sent();
    }
}

void ServerSession::in_sent() {
    if (status == FORWARD) {
        out_async_read();
    } else if (status == UDP_FORWARD) {
        udp_async_read();
    }
}

void ServerSession::out_recv(const string &data) {
    if (status == FORWARD) {
        recv_len += data.length();
        in_async_write(data);
    }
}

void ServerSession::out_sent() {
    if (status == FORWARD) {
        in_async_read();
    }
}

void ServerSession::start_outbound_connect(const shared_ptr<vector<tcp::endpoint> > &endpoints, size_t index, const string &query_addr, const string &query_port) {
    if (status == DESTROY) {
        return;
    }
    if (index >= endpoints->size()) {
        cancel_timer();
        Log::log_with_endpoint(in_endpoint, "cannot establish connection to remote server " + query_addr + ':' + query_port, Log::ERROR);
        destroy();
        return;
    }
    const auto endpoint = (*endpoints)[index];
    Log::log_with_endpoint(in_endpoint, query_addr + " is resolved to " + endpoint.address().to_string(), Log::ALL);
    boost::system::error_code ec;
    if (out_socket.is_open()) {
        out_socket.close(ec);
    }
    out_socket.open(endpoint.protocol(), ec);
    if (ec) {
        start_outbound_connect(endpoints, index + 1, query_addr, query_port);
        return;
    }
    if (config.tcp.no_delay) {
        out_socket.set_option(tcp::no_delay(true), ec);
    }
    if (config.tcp.keep_alive) {
        out_socket.set_option(boost::asio::socket_base::keep_alive(true), ec);
    }
#ifdef TCP_FASTOPEN_CONNECT
    if (config.tcp.fast_open) {
        using fastopen_connect = boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN_CONNECT>;
        out_socket.set_option(fastopen_connect(true), ec);
    }
#endif // TCP_FASTOPEN_CONNECT
    auto self = shared_from_this();
    out_socket.async_connect(endpoint, [this, self, endpoints, index, query_addr, query_port](const boost::system::error_code error) {
        if (status == DESTROY) {
            return;
        }
        if (error) {
            Log::log_with_endpoint(in_endpoint, "cannot connect to " + endpoints->at(index).address().to_string() + ':' + to_string(endpoints->at(index).port()) + ": " + error.message(), Log::ALL);
            start_outbound_connect(endpoints, index + 1, query_addr, query_port);
            return;
        }
        cancel_timer();
        Log::log_with_endpoint(in_endpoint, "tunnel established");
        status = FORWARD;
        out_async_read();
        if (!out_write_buf.empty()) {
            out_async_write(out_write_buf);
        } else {
            in_async_read();
        }
    });
}

void ServerSession::udp_recv(const string &data, const udp::endpoint &endpoint) {
    if (status == UDP_FORWARD) {
        size_t length = data.length();
        Log::log_with_endpoint(in_endpoint, "received a UDP packet of length " + to_string(length) + " bytes from " + endpoint.address().to_string() + ':' + to_string(endpoint.port()));
        recv_len += length;
        in_async_write(UDPPacket::generate(endpoint, data));
    }
}

void ServerSession::udp_sent() {
    if (status == UDP_FORWARD) {
        UDPPacket packet;
        size_t packet_len;
        bool is_packet_valid = packet.parse(udp_data_buf, packet_len);
        if (!is_packet_valid) {
            if (udp_data_buf.length() > MAX_LENGTH) {
                Log::log_with_endpoint(in_endpoint, "UDP packet too long", Log::ERROR);
                destroy();
                return;
            }
            in_async_read();
            return;
        }
        Log::log_with_endpoint(in_endpoint, "sent a UDP packet of length " + to_string(packet.length) + " bytes to " + packet.address.address + ':' + to_string(packet.address.port));
        udp_data_buf = udp_data_buf.substr(packet_len);
        string query_addr = packet.address.address;
        auto self = shared_from_this();
        udp_resolver.async_resolve(query_addr, to_string(packet.address.port), [this, self, packet, query_addr](const boost::system::error_code error, const udp::resolver::results_type& results) {
            if (error || results.empty()) {
                Log::log_with_endpoint(in_endpoint, "cannot resolve remote server hostname " + query_addr + ": " + error.message(), Log::ERROR);
                destroy();
                return;
            }
            auto iterator = results.begin();
            if (config.tcp.prefer_ipv4) {
                for (auto it = results.begin(); it != results.end(); ++it) {
                    const auto &addr = it->endpoint().address();
                    if (addr.is_v4()) {
                        iterator = it;
                        break;
                    }
                }
            }
            Log::log_with_endpoint(in_endpoint, query_addr + " is resolved to " + iterator->endpoint().address().to_string(), Log::ALL);
            if (!udp_socket.is_open()) {
                auto protocol = iterator->endpoint().protocol();
                boost::system::error_code ec;
                udp_socket.open(protocol, ec);
                if (ec) {
                    destroy();
                    return;
                }
                udp_socket.bind(udp::endpoint(protocol, 0));
                udp_async_read();
            }
            sent_len += packet.length;
            udp_async_write(packet.payload, *iterator);
        });
    }
}

void ServerSession::destroy() {
    if (status == DESTROY) {
        return;
    }
    status = DESTROY;
    Log::log_with_endpoint(in_endpoint, "disconnected, " + to_string(recv_len) + " bytes received, " + to_string(sent_len) + " bytes sent, lasted for " + to_string(time(nullptr) - start_time) + " seconds", Log::INFO);
    if (auth && !auth_password.empty()) {
        auth->record(auth_password, recv_len, sent_len);
    }
    boost::system::error_code ec;
    operation_timer.cancel();
    resolver.cancel();
    udp_resolver.cancel();
    if (out_socket.is_open()) {
        out_socket.cancel(ec);
        out_socket.shutdown(tcp::socket::shutdown_both, ec);
        out_socket.close(ec);
    }
    if (udp_socket.is_open()) {
        udp_socket.cancel(ec);
        udp_socket.close(ec);
    }
    if (in_socket.next_layer().is_open()) {
        auto self = shared_from_this();
        auto ssl_shutdown_cb = [this, self](const boost::system::error_code error) {
            if (error == boost::asio::error::operation_aborted) {
                return;
            }
            boost::system::error_code ec;
            ssl_shutdown_timer.cancel();
            in_socket.next_layer().cancel(ec);
            in_socket.next_layer().shutdown(tcp::socket::shutdown_both, ec);
            in_socket.next_layer().close(ec);
        };
        in_socket.next_layer().cancel(ec);
        in_socket.async_shutdown(ssl_shutdown_cb);
        ssl_shutdown_timer.expires_after(chrono::seconds(SSL_SHUTDOWN_TIMEOUT));
        ssl_shutdown_timer.async_wait(ssl_shutdown_cb);
    }
}
