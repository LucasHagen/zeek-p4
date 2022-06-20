#include "FtpMsgAnalyzer.h"

#include <iostream>

#include "RnaOffloaderHdr.h"
#include "RnaPacket.h"
#include "constants.h"
#include "zeek/Conn.h"
#include "zeek/Event.h"
#include "zeek/IPAddr.h"
#include "zeek/analyzer/protocol/ftp/events.bif.h"

using namespace zeek::packet_analysis::BR_UFRGS_INF::RNA::FTP;

using ::zeek::AddrVal;
using ::zeek::AddrValPtr;
using ::zeek::IPAddr;
using ::zeek::Layer3Proto;
using ::zeek::Packet;
using ::zeek::StringVal;
using ::zeek::StringValPtr;
using ::zeek::packet_analysis::Analyzer;

FtpMsgAnalyzer::FtpMsgAnalyzer() : Analyzer("FTP_MSG") {}

bool FtpMsgAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    auto rna_packet = static_cast<RnaPacket*>(packet);
    auto event_hdr = rna_packet->GetOffloaderHdr();
    auto ftp_message_hdr = (const ftp_message_h*)data;
    auto payload = data + sizeof(ftp_message_h);
    auto payload_len = len - sizeof(ftp_message_h);

    auto conn = event_hdr->GetOrCreateConnection(packet,
                                                 /* is_one_way = */ false,
                                                 /* flip_roles = */ true);

    bool is_request;
    switch (ftp_message_hdr->type) {
        case RNA_FTP_MESSAGE_REQUEST:
            is_request = true;
            break;
        case RNA_FTP_MESSAGE_REPLY:
            is_request = false;
            break;
        default:
            is_request = packet->is_orig;
            break;
    }

// #define RNA_UDP_DEBUG
#ifdef RNA_UDP_DEBUG
    std::cout << "[RNA] FTP Message:" << std::endl;
    std::cout << " |_ type     = " << (is_request ? "request" : "reply") << std::endl;
    std::cout << " |_ src_addr = " << packet->ip_hdr->SrcAddr().AsString() << std::endl;
    std::cout << " |_ dst_addr = " << packet->ip_hdr->DstAddr().AsString() << std::endl;
    std::cout << " |_ src_port = " << event_hdr->GetSrcPort() << std::endl;
    std::cout << " |_ dst_port = " << event_hdr->GetDstPort() << std::endl;
    std::cout << " |_ packet->is_orig = " << packet->is_orig << std::endl;
#endif

    TriggerEvents(conn, is_request, payload, payload_len);

    packet->processed = true;

    return true;
}

// Code from `deps/zeek/src/analyzer/protocol/ftp/FTP.cc`
static uint32_t get_reply_code(const int& len, const char* line) {
    if (len >= 3 && isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2])) {
        return (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    } else {
        return 0;
    }
}

bool FtpMsgAnalyzer::TriggerEvents(Connection* conn, bool is_request, const uint8_t* payload,
                                   uint length) {
    // Code from `deps/zeek/src/analyzer/protocol/ftp/FTP.cc`
    const char* line = (const char*)payload;
    const char* end_of_line = line + length;

    EventHandlerPtr f;
    Args vl;

    if (length == 0) return false;

    if (is_request) {
        int cmd_len;
        const char* cmd;
        StringVal* cmd_str;

        line = util::skip_whitespace(line, end_of_line);
        util::get_word(end_of_line - line, line, cmd_len, cmd);
        line = util::skip_whitespace(line + cmd_len, end_of_line);

        if (cmd_len == 0) {
            // Weird("FTP command missing", end_of_line - orig_line, orig_line);
            cmd_str = new StringVal("<missing>");
        } else {
            cmd_str = (new StringVal(cmd_len, cmd))->ToUpper();
        }

        vl = {
            conn->GetVal(),
            IntrusivePtr{AdoptRef{}, cmd_str},
            make_intrusive<StringVal>(end_of_line - line, line),
        };

        f = ftp_request;
    } else {
        uint32_t reply_code = get_reply_code(length, line);

        int cont_resp;
        if (reply_code > 0) {
            line += 3;
        } else {
            return false;
        }

        if (line < end_of_line) {
            line = util::skip_whitespace(line, end_of_line);
        } else {
            line = end_of_line;
        }
        cont_resp = 0;

        if (reply_code == 334) {
            // SSL not supported
            return false;
        }

        vl = {conn->GetVal(), val_mgr->Count(reply_code),
              make_intrusive<StringVal>(end_of_line - line, line), val_mgr->Bool(cont_resp)};

        f = ftp_reply;
    }

    event_mgr.Enqueue(f, std::move(vl));
    return true;
}
