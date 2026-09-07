/* Portable specification of the sparse morph stream and fixed-point blend.
 * The live implementation in src/main/model.c preserves the retail register ABI.
 * The host oracle test executes these ordinary-C reference routines. */
#include "types.h"

#define MODEL_MORPH_VERTEX_INDEX_MASK 0x1fff
#define MODEL_MORPH_HAS_X             0x2000
#define MODEL_MORPH_HAS_Y             0x4000
#define MODEL_MORPH_HAS_Z             0x8000

u16* modelReadMorphDelta(u16* stream, int* dx, int* dy, int* dz);

void modelBlendMorphTargetChunk(u8* baseVertices, u8* outVertices, u16 vertexCount, u16** targetA, u16** targetB,
                                int weightB, u16 firstVertex) {
    u16* a = *targetA;
    u16* b = *targetB;
    int i = 0;
    u32 weightA = 0x10000u - (u32)weightB;
    int indexA;
    int indexB;
    int ax, ay, az;
    int bx, by, bz;

    while (i < vertexCount) {
        indexA = (*(s16*)a & MODEL_MORPH_VERTEX_INDEX_MASK) - firstVertex;
        indexB = (*(s16*)b & MODEL_MORPH_VERTEX_INDEX_MASK) - firstVertex;
        if (i >= indexA) {
            if (i == indexB) {
                b = modelReadMorphDelta(b, &bx, &by, &bz);
                a = modelReadMorphDelta(a, &ax, &ay, &az);
                *(u16*)outVertices = (((u32)ax * weightA + (u32)bx * (u32)weightB) >> 16) + *(s16*)baseVertices;
                *(u16*)(outVertices + 2) =
                    (((u32)ay * weightA + (u32)by * (u32)weightB) >> 16) + *(s16*)(baseVertices + 2);
                *(u16*)(outVertices + 4) =
                    (((u32)az * weightA + (u32)bz * (u32)weightB) >> 16) + *(s16*)(baseVertices + 4);
            } else {
                a = modelReadMorphDelta(a, &ax, &ay, &az);
                *(u16*)outVertices = (((u32)ax * weightA) >> 16) + *(s16*)baseVertices;
                *(u16*)(outVertices + 2) = (((u32)ay * weightA) >> 16) + *(s16*)(baseVertices + 2);
                *(u16*)(outVertices + 4) = (((u32)az * weightA) >> 16) + *(s16*)(baseVertices + 4);
            }
        } else if (i >= indexB) {
            b = modelReadMorphDelta(b, &bx, &by, &bz);
            *(u16*)outVertices = (((u32)bx * (u32)weightB) >> 16) + *(s16*)baseVertices;
            *(u16*)(outVertices + 2) = (((u32)by * (u32)weightB) >> 16) + *(s16*)(baseVertices + 2);
            *(u16*)(outVertices + 4) = (((u32)bz * (u32)weightB) >> 16) + *(s16*)(baseVertices + 4);
        } else {
            *(u32*)outVertices = *(u32*)baseVertices;
            *(u16*)(outVertices + 4) = *(s16*)(baseVertices + 4);
        }
        baseVertices += 6;
        outVertices += 6;
        i++;
    }
    *targetA = a;
    *targetB = b;
}

u16* modelReadMorphDelta(u16* stream, int* dx, int* dy, int* dz) {
    u16 flags = *stream;

    stream++;
    *dx = 0;
    if (flags & MODEL_MORPH_HAS_X) {
        *dx = *(s16*)stream;
        stream++;
    }
    *dy = 0;
    if (flags & MODEL_MORPH_HAS_Y) {
        *dy = *(s16*)stream;
        stream++;
    }
    *dz = 0;
    if (flags & MODEL_MORPH_HAS_Z) {
        *dz = *(s16*)stream;
        stream++;
    }
    return stream;
}
