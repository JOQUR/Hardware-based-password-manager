// Code generated by bitproto. DO NOT EDIT.

#include "bitproto.h"
#include "messaging_bp.h"

void BpXXXProcessArrayInitializeComm1(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 32, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayInitializeComm1(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 32, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpFieldDescriptorsInitInitializeComm(struct InitializeComm *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->public_key), BpArray(256, 32 * sizeof(uint8_t), BpXXXProcessArrayInitializeComm1, BpXXXJsonFormatArrayInitializeComm1), "public_key");
}

void BpXXXProcessInitializeComm(void *data, struct BpProcessorContext *ctx) {
    struct InitializeComm *m = (struct InitializeComm *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitInitializeComm(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 256, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatInitializeComm(void *data, struct BpJsonFormatContext *ctx) {
    struct InitializeComm *m = (struct InitializeComm *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitInitializeComm(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 256, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeInitializeComm(struct InitializeComm *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessInitializeComm((void *)m, &ctx);
    return 0;
}

int DecodeInitializeComm(struct InitializeComm *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessInitializeComm((void *)m, &ctx);
    return 0;
}

int JsonInitializeComm(struct InitializeComm *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatInitializeComm((void *)m, &ctx);
    return ctx.n;
}

void BpXXXProcessArrayInitializeCommRsp1(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 32, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXProcessArrayInitializeCommRsp2(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayInitializeCommRsp1(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 32, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayInitializeCommRsp2(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpFieldDescriptorsInitInitializeCommRsp(struct InitializeCommRsp *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->public_key), BpArray(256, 32 * sizeof(uint8_t), BpXXXProcessArrayInitializeCommRsp1, BpXXXJsonFormatArrayInitializeCommRsp1), "public_key");
    fds[1] = BpMessageFieldDescriptor((void *)&(m->initialization_vector), BpArray(128, 16 * sizeof(uint8_t), BpXXXProcessArrayInitializeCommRsp2, BpXXXJsonFormatArrayInitializeCommRsp2), "initialization_vector");
}

void BpXXXProcessInitializeCommRsp(void *data, struct BpProcessorContext *ctx) {
    struct InitializeCommRsp *m = (struct InitializeCommRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[2];
    BpFieldDescriptorsInitInitializeCommRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 2, 384, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatInitializeCommRsp(void *data, struct BpJsonFormatContext *ctx) {
    struct InitializeCommRsp *m = (struct InitializeCommRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[2];
    BpFieldDescriptorsInitInitializeCommRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 2, 384, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeInitializeCommRsp(struct InitializeCommRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessInitializeCommRsp((void *)m, &ctx);
    return 0;
}

int DecodeInitializeCommRsp(struct InitializeCommRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessInitializeCommRsp((void *)m, &ctx);
    return 0;
}

int JsonInitializeCommRsp(struct InitializeCommRsp *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatInitializeCommRsp((void *)m, &ctx);
    return ctx.n;
}

void BpXXXProcessArrayChallange1(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayChallange1(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpFieldDescriptorsInitChallange(struct Challange *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->challange_buffer), BpArray(128, 16 * sizeof(uint8_t), BpXXXProcessArrayChallange1, BpXXXJsonFormatArrayChallange1), "challange_buffer");
}

void BpXXXProcessChallange(void *data, struct BpProcessorContext *ctx) {
    struct Challange *m = (struct Challange *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitChallange(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 128, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatChallange(void *data, struct BpJsonFormatContext *ctx) {
    struct Challange *m = (struct Challange *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitChallange(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 128, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeChallange(struct Challange *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessChallange((void *)m, &ctx);
    return 0;
}

int DecodeChallange(struct Challange *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessChallange((void *)m, &ctx);
    return 0;
}

int JsonChallange(struct Challange *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatChallange((void *)m, &ctx);
    return ctx.n;
}

void BpXXXProcessArrayChallangeRsp1(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayChallangeRsp1(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpFieldDescriptorsInitChallangeRsp(struct ChallangeRsp *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->challange_buffer), BpArray(128, 16 * sizeof(uint8_t), BpXXXProcessArrayChallangeRsp1, BpXXXJsonFormatArrayChallangeRsp1), "challange_buffer");
}

void BpXXXProcessChallangeRsp(void *data, struct BpProcessorContext *ctx) {
    struct ChallangeRsp *m = (struct ChallangeRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitChallangeRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 128, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatChallangeRsp(void *data, struct BpJsonFormatContext *ctx) {
    struct ChallangeRsp *m = (struct ChallangeRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitChallangeRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 128, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeChallangeRsp(struct ChallangeRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessChallangeRsp((void *)m, &ctx);
    return 0;
}

int DecodeChallangeRsp(struct ChallangeRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessChallangeRsp((void *)m, &ctx);
    return 0;
}

int JsonChallangeRsp(struct ChallangeRsp *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatChallangeRsp((void *)m, &ctx);
    return ctx.n;
}

void BpFieldDescriptorsInitHandshakeFinished(struct HandshakeFinished *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->ack), BpBool(), "ack");
}

void BpXXXProcessHandshakeFinished(void *data, struct BpProcessorContext *ctx) {
    struct HandshakeFinished *m = (struct HandshakeFinished *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitHandshakeFinished(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 1, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatHandshakeFinished(void *data, struct BpJsonFormatContext *ctx) {
    struct HandshakeFinished *m = (struct HandshakeFinished *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitHandshakeFinished(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 1, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeHandshakeFinished(struct HandshakeFinished *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessHandshakeFinished((void *)m, &ctx);
    return 0;
}

int DecodeHandshakeFinished(struct HandshakeFinished *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessHandshakeFinished((void *)m, &ctx);
    return 0;
}

int JsonHandshakeFinished(struct HandshakeFinished *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatHandshakeFinished((void *)m, &ctx);
    return ctx.n;
}

void BpFieldDescriptorsInitHandshakeFinishedRsp(struct HandshakeFinishedRsp *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->ack), BpBool(), "ack");
}

void BpXXXProcessHandshakeFinishedRsp(void *data, struct BpProcessorContext *ctx) {
    struct HandshakeFinishedRsp *m = (struct HandshakeFinishedRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitHandshakeFinishedRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 1, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatHandshakeFinishedRsp(void *data, struct BpJsonFormatContext *ctx) {
    struct HandshakeFinishedRsp *m = (struct HandshakeFinishedRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitHandshakeFinishedRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 1, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeHandshakeFinishedRsp(struct HandshakeFinishedRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessHandshakeFinishedRsp((void *)m, &ctx);
    return 0;
}

int DecodeHandshakeFinishedRsp(struct HandshakeFinishedRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessHandshakeFinishedRsp((void *)m, &ctx);
    return 0;
}

int JsonHandshakeFinishedRsp(struct HandshakeFinishedRsp *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatHandshakeFinishedRsp((void *)m, &ctx);
    return ctx.n;
}

void BpXXXProcessArrayCreateUser1(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXProcessArrayCreateUser2(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 32, BpUint(8, sizeof(uint8_t)));
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayCreateUser1(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 16, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayCreateUser2(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 32, BpUint(8, sizeof(uint8_t)));
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpFieldDescriptorsInitCreateUser(struct CreateUser *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->username), BpArray(128, 16 * sizeof(uint8_t), BpXXXProcessArrayCreateUser1, BpXXXJsonFormatArrayCreateUser1), "username");
    fds[1] = BpMessageFieldDescriptor((void *)&(m->password_hash), BpArray(256, 32 * sizeof(uint8_t), BpXXXProcessArrayCreateUser2, BpXXXJsonFormatArrayCreateUser2), "password_hash");
}

void BpXXXProcessCreateUser(void *data, struct BpProcessorContext *ctx) {
    struct CreateUser *m = (struct CreateUser *)(data);
    struct BpMessageFieldDescriptor field_descriptors[2];
    BpFieldDescriptorsInitCreateUser(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 2, 384, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatCreateUser(void *data, struct BpJsonFormatContext *ctx) {
    struct CreateUser *m = (struct CreateUser *)(data);
    struct BpMessageFieldDescriptor field_descriptors[2];
    BpFieldDescriptorsInitCreateUser(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 2, 384, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeCreateUser(struct CreateUser *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessCreateUser((void *)m, &ctx);
    return 0;
}

int DecodeCreateUser(struct CreateUser *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessCreateUser((void *)m, &ctx);
    return 0;
}

int JsonCreateUser(struct CreateUser *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatCreateUser((void *)m, &ctx);
    return ctx.n;
}

void BpFieldDescriptorsInitCreateUserRsp(struct CreateUserRsp *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->ack), BpBool(), "ack");
}

void BpXXXProcessCreateUserRsp(void *data, struct BpProcessorContext *ctx) {
    struct CreateUserRsp *m = (struct CreateUserRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitCreateUserRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 1, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatCreateUserRsp(void *data, struct BpJsonFormatContext *ctx) {
    struct CreateUserRsp *m = (struct CreateUserRsp *)(data);
    struct BpMessageFieldDescriptor field_descriptors[1];
    BpFieldDescriptorsInitCreateUserRsp(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 1, 1, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeCreateUserRsp(struct CreateUserRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessCreateUserRsp((void *)m, &ctx);
    return 0;
}

int DecodeCreateUserRsp(struct CreateUserRsp *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessCreateUserRsp((void *)m, &ctx);
    return 0;
}

int JsonCreateUserRsp(struct CreateUserRsp *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatCreateUserRsp((void *)m, &ctx);
    return ctx.n;
}

void BpFieldDescriptorsInitMessages(struct Messages *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->id), BpEnum(8, sizeof(MessageId)), "id");
    fds[1] = BpMessageFieldDescriptor((void *)&(m->init_comm), BpMessage(256, sizeof(struct InitializeComm), BpXXXProcessInitializeComm, BpXXXJsonFormatInitializeComm), "init_comm");
    fds[2] = BpMessageFieldDescriptor((void *)&(m->challange), BpMessage(128, sizeof(struct Challange), BpXXXProcessChallange, BpXXXJsonFormatChallange), "challange");
    fds[3] = BpMessageFieldDescriptor((void *)&(m->handshake_finished), BpMessage(1, sizeof(struct HandshakeFinished), BpXXXProcessHandshakeFinished, BpXXXJsonFormatHandshakeFinished), "handshake_finished");
    fds[4] = BpMessageFieldDescriptor((void *)&(m->user_creation), BpMessage(384, sizeof(struct CreateUser), BpXXXProcessCreateUser, BpXXXJsonFormatCreateUser), "user_creation");
}

void BpXXXProcessMessages(void *data, struct BpProcessorContext *ctx) {
    struct Messages *m = (struct Messages *)(data);
    struct BpMessageFieldDescriptor field_descriptors[5];
    BpFieldDescriptorsInitMessages(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 5, 777, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatMessages(void *data, struct BpJsonFormatContext *ctx) {
    struct Messages *m = (struct Messages *)(data);
    struct BpMessageFieldDescriptor field_descriptors[5];
    BpFieldDescriptorsInitMessages(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 5, 777, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeMessages(struct Messages *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessMessages((void *)m, &ctx);
    return 0;
}

int DecodeMessages(struct Messages *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessMessages((void *)m, &ctx);
    return 0;
}

int JsonMessages(struct Messages *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatMessages((void *)m, &ctx);
    return ctx.n;
}

void BpFieldDescriptorsInitResponses(struct Responses *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->id), BpEnum(8, sizeof(MessageId)), "id");
    fds[1] = BpMessageFieldDescriptor((void *)&(m->init_comm), BpMessage(384, sizeof(struct InitializeCommRsp), BpXXXProcessInitializeCommRsp, BpXXXJsonFormatInitializeCommRsp), "init_comm");
    fds[2] = BpMessageFieldDescriptor((void *)&(m->challange), BpMessage(128, sizeof(struct ChallangeRsp), BpXXXProcessChallangeRsp, BpXXXJsonFormatChallangeRsp), "challange");
    fds[3] = BpMessageFieldDescriptor((void *)&(m->handshake_finished), BpMessage(1, sizeof(struct HandshakeFinishedRsp), BpXXXProcessHandshakeFinishedRsp, BpXXXJsonFormatHandshakeFinishedRsp), "handshake_finished");
    fds[4] = BpMessageFieldDescriptor((void *)&(m->user_creation), BpMessage(1, sizeof(struct CreateUserRsp), BpXXXProcessCreateUserRsp, BpXXXJsonFormatCreateUserRsp), "user_creation");
}

void BpXXXProcessResponses(void *data, struct BpProcessorContext *ctx) {
    struct Responses *m = (struct Responses *)(data);
    struct BpMessageFieldDescriptor field_descriptors[5];
    BpFieldDescriptorsInitResponses(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 5, 522, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatResponses(void *data, struct BpJsonFormatContext *ctx) {
    struct Responses *m = (struct Responses *)(data);
    struct BpMessageFieldDescriptor field_descriptors[5];
    BpFieldDescriptorsInitResponses(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 5, 522, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeResponses(struct Responses *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessResponses((void *)m, &ctx);
    return 0;
}

int DecodeResponses(struct Responses *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessResponses((void *)m, &ctx);
    return 0;
}

int JsonResponses(struct Responses *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatResponses((void *)m, &ctx);
    return ctx.n;
}