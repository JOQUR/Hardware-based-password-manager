// Code generated by bitproto. DO NOT EDIT.

#include "bitproto.h"
#include "messaging_bp.h"

void BpXXXProcessTimestamp(void *data, struct BpProcessorContext *ctx) {
    struct BpAliasDescriptor descriptor = BpAliasDescriptor(BpInt(64, sizeof(int64_t)));
    BpEndecodeAlias(&descriptor, ctx, data);
}

void BpXXXJsonFormatTimestamp(void *data, struct BpJsonFormatContext *ctx) {
    struct BpAliasDescriptor descriptor = BpAliasDescriptor(BpInt(64, sizeof(int64_t)));
    BpJsonFormatAlias(&descriptor, ctx, data);
}

void BpXXXProcessDupa(void *data, struct BpProcessorContext *ctx) {
    struct BpAliasDescriptor descriptor = BpAliasDescriptor(BpInt(8, sizeof(int8_t)));
    BpEndecodeAlias(&descriptor, ctx, data);
}

void BpXXXJsonFormatDupa(void *data, struct BpJsonFormatContext *ctx) {
    struct BpAliasDescriptor descriptor = BpAliasDescriptor(BpInt(8, sizeof(int8_t)));
    BpJsonFormatAlias(&descriptor, ctx, data);
}

void BpXXXProcessArrayShit2(void *data, struct BpProcessorContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 8, BpByte());
    BpEndecodeArray(&descriptor, ctx, data);
}

void BpXXXJsonFormatArrayShit2(void *data, struct BpJsonFormatContext *ctx) {
    struct BpArrayDescriptor descriptor = BpArrayDescriptor(false, 8, BpByte());
    BpJsonFormatArray(&descriptor, ctx, data);
}

void BpFieldDescriptorsInitShit(struct Shit *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->jeden), BpBool(), "jeden");
    fds[1] = BpMessageFieldDescriptor((void *)&(m->array), BpArray(64, 8 * sizeof(unsigned char), BpXXXProcessArrayShit2, BpXXXJsonFormatArrayShit2), "array");
    fds[2] = BpMessageFieldDescriptor((void *)&(m->ptr), BpUint(41, sizeof(uint64_t)), "ptr");
}

void BpXXXProcessShit(void *data, struct BpProcessorContext *ctx) {
    struct Shit *m = (struct Shit *)(data);
    struct BpMessageFieldDescriptor field_descriptors[3];
    BpFieldDescriptorsInitShit(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 3, 106, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatShit(void *data, struct BpJsonFormatContext *ctx) {
    struct Shit *m = (struct Shit *)(data);
    struct BpMessageFieldDescriptor field_descriptors[3];
    BpFieldDescriptorsInitShit(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 3, 106, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodeShit(struct Shit *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessShit((void *)m, &ctx);
    return 0;
}

int DecodeShit(struct Shit *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessShit((void *)m, &ctx);
    return 0;
}

int JsonShit(struct Shit *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatShit((void *)m, &ctx);
    return ctx.n;
}

void BpFieldDescriptorsInitPen(struct Pen *m, struct BpMessageFieldDescriptor *fds) {
    fds[0] = BpMessageFieldDescriptor((void *)&(m->color), BpEnum(3, sizeof(Color)), "color");
    fds[1] = BpMessageFieldDescriptor((void *)&(m->produced_at), BpAlias(64, sizeof(Timestamp), BpXXXProcessTimestamp, BpXXXJsonFormatTimestamp, BP_TYPE_INT), "produced_at");
    fds[2] = BpMessageFieldDescriptor((void *)&(m->dupa), BpAlias(8, sizeof(Dupa), BpXXXProcessDupa, BpXXXJsonFormatDupa, BP_TYPE_INT), "dupa");
    fds[3] = BpMessageFieldDescriptor((void *)&(m->shit), BpMessage(106, sizeof(struct Shit), BpXXXProcessShit, BpXXXJsonFormatShit), "shit");
}

void BpXXXProcessPen(void *data, struct BpProcessorContext *ctx) {
    struct Pen *m = (struct Pen *)(data);
    struct BpMessageFieldDescriptor field_descriptors[4];
    BpFieldDescriptorsInitPen(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 4, 181, field_descriptors);
    BpEndecodeMessage(&descriptor, ctx, data);
}

void BpXXXJsonFormatPen(void *data, struct BpJsonFormatContext *ctx) {
    struct Pen *m = (struct Pen *)(data);
    struct BpMessageFieldDescriptor field_descriptors[4];
    BpFieldDescriptorsInitPen(m, field_descriptors);
    struct BpMessageDescriptor descriptor = BpMessageDescriptor(false, 4, 181, field_descriptors);
    BpJsonFormatMessage(&descriptor, ctx, data);
}

int EncodePen(struct Pen *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(true, s);
    BpXXXProcessPen((void *)m, &ctx);
    return 0;
}

int DecodePen(struct Pen *m, unsigned char *s) {
    struct BpProcessorContext ctx = BpProcessorContext(false, s);
    BpXXXProcessPen((void *)m, &ctx);
    return 0;
}

int JsonPen(struct Pen *m, char *s) {
    struct BpJsonFormatContext ctx = BpJsonFormatContext(s);
    BpXXXJsonFormatPen((void *)m, &ctx);
    return ctx.n;
}