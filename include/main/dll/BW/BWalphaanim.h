#ifndef MAIN_DLL_BW_BWALPHAANIM_H_
#define MAIN_DLL_BW_BWALPHAANIM_H_

#include "ghidra_import.h"

/* Per-object extra state for the rideable SnowBike / CloudRunner bike.
 * Offsets recovered from SnowBike_init/SnowBike_update derefs; the
 * 0x178..0x3DC block is the gPathControlInterface curves-collision state
 * and the 0x428 byte carries the SnowBikeFlags bitfield overlay. */
typedef struct SnowBikeState {
    u8 pad000[0xc];
    f32 unk00C;             /* 0x00c: position snapshot X */
    f32 unk010;             /* 0x010: position snapshot Y */
    f32 unk014;             /* 0x014: position snapshot Z */
    f32 unk018;             /* 0x018 */
    f32 unk01C;             /* 0x01c */
    f32 unk020;             /* 0x020 */
    f32 unk024;             /* 0x024 */
    u8 pad028[0x4];
    s16 unk02C;             /* 0x02c: rider yaw on free */
    s16 unk02E;             /* 0x02e: rider pitch on free */
    u8 pad030[0x8];
    int unk038;             /* 0x038 */
    int unk03C;             /* 0x03c */
    int unk040;             /* 0x040 */
    u8 pad044[0x8];
    f32 unk04C;             /* 0x04c: rider pos X on free */
    f32 unk050;             /* 0x050: rider pos Y on free */
    f32 unk054;             /* 0x054: rider pos Z on free */
    u8 unk058;              /* 0x058 */
    u8 pad059[0x3];
    u8 unk05C;              /* 0x05c */
    u8 unk05D;              /* 0x05d */
    u8 pad05E[0x2];
    char *unk060;           /* 0x060 */
    u8 pad064[0x1];
    s8 unk065;              /* 0x065: collision channel (-1 none) */
    u8 pad066[0x2];
    f32 unk068;             /* 0x068 */
    u8 pad06C[0x374];       /* 0x178: path-control block lives in here */
    f32 unk3E0;             /* 0x3e0 */
    f32 unk3E4;             /* 0x3e4 */
    u8 pad3E8[0xc];
    f32 unk3F4;             /* 0x3f4 */
    f32 unk3F8;             /* 0x3f8 */
    u8 pad3FC[0x10];
    s16 unk40C;             /* 0x40c: yaw current */
    s16 unk40E;             /* 0x40e: yaw target */
    u8 pad410[0xc];
    s16 unk41C;             /* 0x41c */
    s16 unk41E;             /* 0x41e */
    u8 unk420;              /* 0x420 */
    s8 unk421;              /* 0x421: rider mode */
    u8 pad422[0xe];
    f32 unk430;             /* 0x430 */
    u8 unk434;              /* 0x434: bike kind */
    u8 unk435;              /* 0x435: variant */
    u8 pad436[0x2];
    f32 unk438;             /* 0x438 */
    u8 pad43C[0x4];
    s16 unk440;             /* 0x440: model id */
    u8 pad442[0x6];
    s16 unk448;             /* 0x448 */
    s16 unk44A;             /* 0x44a: gamebit id */
    s16 unk44C;             /* 0x44c */
    u8 pad44E[0x2];
    u32 unk450;             /* 0x450 */
    u32 unk454;             /* 0x454 */
    u32 unk458;             /* 0x458 */
    f32 unk45C;             /* 0x45c */
    s8 unk460;              /* 0x460 */
    u8 pad461[0x3];
    f32 unk464;             /* 0x464 */
    f32 unk468;             /* 0x468 */
    f32 unk46C;             /* 0x46c */
    f32 unk470;             /* 0x470 */
    f32 unk474;             /* 0x474 */
    f32 unk478;             /* 0x478 */
    f32 unk47C;             /* 0x47c */
    f32 unk480;             /* 0x480 */
    f32 unk484;             /* 0x484 */
    u8 pad488[0xc];
    f32 unk494;             /* 0x494 */
    f32 unk498;             /* 0x498 */
    f32 unk49C;             /* 0x49c */
    u8 pad4A0[0x10];
    f32 unk4B0;             /* 0x4b0 */
    u8 pad4B4[0x4];
    f32 unk4B8;             /* 0x4b8 */
    f32 unk4BC;             /* 0x4bc */
    f32 unk4C0;             /* 0x4c0 */
    f32 unk4C4;             /* 0x4c4 */
    u8 pad4C8[0x54];        /* 0x4c8: 9 path allocation slots (stride 8) */
    f32 unk51C;             /* 0x51c: home X */
    f32 unk520;             /* 0x520: home Y */
    f32 unk524;             /* 0x524: home Z */
    u8 pad528[0x10];
    f32 unk538;             /* 0x538 */
    u8 pad53C[0x4];
    f32 unk540;             /* 0x540 */
    f32 unk544;             /* 0x544 */
    f32 unk548;             /* 0x548 */
    f32 unk54C;             /* 0x54c */
} SnowBikeState; /* extends to at least 0x550 */

void SnowBike_update(int obj);

#endif /* MAIN_DLL_BW_BWALPHAANIM_H_ */
