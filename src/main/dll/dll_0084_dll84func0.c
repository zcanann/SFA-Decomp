#include "main/effect_interfaces.h"
#include "main/dll/foodbag.h"


extern u32 randomGetRange(int min, int max);

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80314E08[];
extern f32 lbl_803E0D88;
extern f32 lbl_803E0D8C;
extern f32 lbl_803E0D90;
extern f32 lbl_803E0D94;
extern f32 lbl_803E0D98;
extern f32 lbl_803E0D9C;
extern f32 lbl_803E0DA0;
extern f32 lbl_803E0DA4;
extern f32 lbl_803E0DA8;
extern f32 lbl_803E0DAC;
extern f32 lbl_803E0DB0;
extern f32 lbl_803E0DB4;
extern f32 lbl_803E0DB8;
extern f32 lbl_803E0DBC;
extern f32 lbl_803E0DC0;
extern f32 lbl_803E0DC4;
extern f32 lbl_803E0DC8;
extern f32 lbl_803E0DCC;
extern f32 lbl_803E0DD0;
extern u8 lbl_80315030[];
extern int lbl_803DD4B0;
extern f32 lbl_803E0DD8;
extern f32 lbl_803E0DDC;
extern f32 lbl_803E0DE0;
extern f32 lbl_803E0DE4;
extern f32 lbl_803E0DE8;
extern f32 lbl_803E0DEC;
extern f32 lbl_803E0DF0;
extern f32 lbl_803E0DF4;
extern f32 lbl_803E0DF8;
extern u8 lbl_80315258[];
extern u8 lbl_803DB8E0;
extern f32 lbl_803E0E00;
extern f32 lbl_803E0E04;
extern f32 lbl_803E0E08;
extern f32 lbl_803E0E0C;
extern f32 lbl_803E0E10;
extern f32 lbl_803E0E14;
extern f32 lbl_803E0E18;
extern f32 lbl_803E0E1C;
extern u8 lbl_80315328[];
extern u8 lbl_803DB8E8;
extern f32 lbl_803E0E20;
extern f32 lbl_803E0E24;
extern f32 lbl_803E0E28;
extern f32 lbl_803E0E2C;
extern f32 lbl_803E0E30;
extern f32 lbl_803E0E34;
extern f32 lbl_803E0E38;
extern f32 lbl_803E0E3C;
extern f32 lbl_803E0E40;
extern f32 lbl_803E0E44;
extern f32 lbl_803E0E48;
extern f32 lbl_803E0E4C;
extern f32 lbl_803E0E50;
extern f32 lbl_803E0E54;
extern u8 lbl_80315548[];
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;
extern f32 lbl_803E0E90;
extern f32 lbl_803E0E94;
extern f32 lbl_803E0E98;
extern f32 lbl_803E0E9C;
extern f32 lbl_803E0EA0;
extern f32 lbl_803E0EA4;
extern f32 lbl_803E0EA8;
extern u8 lbl_80315770[];
extern f32 lbl_803E0EB0;
extern f32 lbl_803E0EB4;
extern f32 lbl_803E0EB8;
extern f32 lbl_803E0EBC;
extern f32 lbl_803E0EC0;
extern f32 lbl_803E0EC4;
extern f32 lbl_803E0EC8;
extern f32 lbl_803E0ECC;
extern f32 lbl_803E0ED0;
extern f32 lbl_803E0ED8;
extern f32 lbl_803E0EDC;
extern f32 lbl_803E0EE0;
extern f32 lbl_803E0EE4;
extern f32 lbl_803E0EE8;
extern f32 lbl_803E0EEC;
extern f32 lbl_803E0EF0;
extern f32 lbl_803E0EF4;
extern f32 lbl_803E0EF8;
extern f32 lbl_803E0EFC;
extern f32 lbl_803E0F00;
extern f32 lbl_803E0F04;
extern f32 lbl_803E0F08;
extern f32 lbl_803E0F0C;
extern f32 lbl_803E0F10;
extern f32 lbl_803E0F14;
extern f32 lbl_803E0F18;
extern u8 lbl_80315998[];
extern u8 lbl_80315CA8[];
extern f32 lbl_803E0F20;
extern f32 lbl_803E0F24;
extern f32 lbl_803E0F28;
extern f32 lbl_803E0F2C;
extern f32 lbl_803E0F30;
extern f32 lbl_803E0F34;
extern f32 lbl_803E0F38;
extern f32 lbl_803E0F3C;
extern f32 lbl_803E0F40;
extern f32 lbl_803E0F44;
extern f32 lbl_803E0F48;
extern f32 lbl_803E0F4C;
extern f32 lbl_803E0F50;
extern f32 lbl_803E0F54;
extern f32 lbl_803E0F58;
extern f32 lbl_803E0F5C;
extern f32 lbl_803E0F60;
extern f32 lbl_803E0F64;
extern f32 lbl_803E0F68;
extern f32 lbl_803E0F6C;
extern u8 lbl_80316650[];
extern f32 lbl_803E1050;
extern f32 lbl_803E1054;
extern f32 lbl_803E1058;
extern u8 lbl_80316020[];
extern f32 lbl_803E0FB0;
extern f32 lbl_803E0FB4;
extern f32 lbl_803E0FB8;
extern f32 lbl_803E0FBC;
extern f32 lbl_803E0FC0;
extern f32 lbl_803E0FC4;
extern f32 lbl_803E0FC8;
extern f32 lbl_803E0FCC;
extern f32 lbl_803E0FD0;
extern f32 lbl_803E0FD4;
extern f32 lbl_803E0FD8;
extern u8 lbl_80316E30[];
extern u8 lbl_803DB920;
extern f32 lbl_803E11A0;
extern f32 lbl_803E11A4;
extern f32 lbl_803E11A8;
extern f32 lbl_803E11AC;
extern f32 lbl_803E11B0;
extern f32 lbl_803E11B4;
extern f32 lbl_803E11B8;
extern f32 lbl_803E11BC;
extern f32 lbl_803E11C0;
extern f32 lbl_803E11C4;
extern f32 lbl_803E11C8;
extern f32 lbl_803E11CC;
extern f32 lbl_803E11D0;
extern f32 lbl_803E11D4;
extern u8 lbl_80316950[];
extern f32 lbl_803E10B0;
extern f32 lbl_803E10B4;
extern f32 lbl_803E10B8;
extern f32 lbl_803E10BC;
extern f32 lbl_803E10C0;
extern f32 lbl_803E10C4;
extern f32 lbl_803E10C8;
extern f32 lbl_803E10CC;
extern f32 lbl_803E10D0;
extern f32 lbl_803E10D4;
extern u8 lbl_80316728[];
extern f32 lbl_803E1060;
extern f32 lbl_803E1064;
extern f32 lbl_803E1068;
extern f32 lbl_803E106C;
extern f32 lbl_803E1070;
extern f32 lbl_803E1074;
extern f32 lbl_803E1078;
extern f32 lbl_803E107C;
extern f32 lbl_803E1080;
extern f32 lbl_803E1084;
extern f32 lbl_803E1088;
extern f32 lbl_803E108C;
extern f32 lbl_803E1090;
extern f32 lbl_803E1094;
extern f32 lbl_803E1098;
extern f32 lbl_803E109C;
extern f32 lbl_803E10A0;
extern f32 lbl_803E10A4;
extern u8 lbl_80315FA8[];
extern u8 lbl_803DB8F0;
extern u8 lbl_803DB8F4;
extern u8 lbl_803DB8FC;
extern f32 lbl_803E0F70;
extern f32 lbl_803E0F74;
extern f32 lbl_803E0F78;
extern f32 lbl_803E0F7C;
extern f32 lbl_803E0F80;
extern f32 lbl_803E0F84;
extern f32 lbl_803E0F88;
extern f32 lbl_803E0F8C;
extern f32 lbl_803E0F90;
extern f32 lbl_803E0F94;
extern f32 lbl_803E0F98;
extern f32 lbl_803E0F9C;
extern f32 lbl_803E0FA0;
extern u8 lbl_80316C60[];
extern u8 lbl_80316C40[];
extern u8 lbl_803DB918;
extern u8 lbl_803DB910;
extern f32 lbl_803E1138;
extern f32 lbl_803E113C;
extern f32 lbl_803E1140;
extern f32 lbl_803E1144;
extern f32 lbl_803E1148;
extern f32 lbl_803E114C;
extern f32 lbl_803E1150;
extern f32 lbl_803E1154;
extern f32 lbl_803E1158;
extern f32 lbl_803E115C;
extern f32 lbl_803E1160;
extern f32 lbl_803E1164;
extern f32 lbl_803E1168;
extern f32 lbl_803E116C;
extern u8 lbl_80316B60[];
extern f32 lbl_803E10E0;
extern f32 lbl_803E10E4;
extern f32 lbl_803E10E8;
extern f32 lbl_803E10EC;
extern f32 lbl_803E10F0;
extern f32 lbl_803E10F4;
extern f32 lbl_803E10F8;
extern f32 lbl_803E10FC;
extern f32 lbl_803E1100;
extern f32 lbl_803E1104;
extern f32 lbl_803E1108;
extern f32 lbl_803E110C;
extern f32 lbl_803E1110;
extern f32 lbl_803E1114;
extern f32 lbl_803E1118;
extern f32 lbl_803E111C;
extern f32 lbl_803E1120;
extern f32 lbl_803E1124;
extern f32 lbl_803E1128;
extern u8 lbl_80315468[];
extern u8 lbl_80316240[];
extern f32 lbl_803E1010;
extern f32 lbl_803E1014;
extern f32 lbl_803E1018;
extern f32 lbl_803E101C;
extern f32 lbl_803E1020;
extern f32 lbl_803E1024;
extern u8 lbl_80316460[];
extern u8 lbl_803DB908;
extern f32 lbl_803E1028;
extern f32 lbl_803E102C;
extern f32 lbl_803E1030;
extern f32 lbl_803E1034;
extern f32 lbl_803E1038;
extern f32 lbl_803E103C;
extern f32 lbl_803E1040;
extern f32 lbl_803E1044;
extern f32 lbl_803E1048;
extern u8 lbl_80316050[];
extern u8 lbl_803DB900;
extern f32 lbl_803E0FE8;
extern f32 lbl_803E0FEC;
extern f32 lbl_803E0FF0;
extern f32 lbl_803E0FF4;
extern f32 lbl_803E0FF8;
extern f32 lbl_803E0FFC;
extern f32 lbl_803E1000;
extern f32 lbl_803E1004;
extern f32 lbl_803E1008;
extern u8 lbl_80316C90[];
extern f32 lbl_803E1178;
extern f32 lbl_803E117C;
extern f32 lbl_803E1180;
extern f32 lbl_803E1184;
extern f32 lbl_803E1188;
extern f32 lbl_803E118C;
extern f32 lbl_803E1190;
extern f32 lbl_803E1194;
extern f32 lbl_803E1198;
extern f32 lbl_803E119C;
extern f32 lbl_803E0E58;
extern f32 lbl_803E0E5C;
extern f32 lbl_803E0E60;
extern f32 lbl_803E0E64;
extern f32 lbl_803E0E68;
extern f32 lbl_803E0E6C;
extern f32 lbl_803E0E70;
extern f32 lbl_803E0E74;

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    u16 flags;
    u8 layer;
} FbCmd;

typedef struct
{
    FbCmd* cmds;
    int ctx;
    u8 pad0[0x18];
    f32 col[3];
    f32 pos[3];
    f32 scale;
    u32 v3c;
    u32 v40;
    s16 v44;
    s16 hw[7];
    u32 flags;
    u8 v58, v59, v5a, v5b, v5c;
    s8 count;
    u8 pad1[2];
    FbCmd entries[32];
} FbBuf;

/*
 * --INFO--
 *
 * Function: dll_7C_func03
 * EN v1.0 Address: 0x800F472C
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: 0x800F49C8
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7C_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_7D_func03
 * EN v1.0 Address: 0x800F4C70
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x800F4F0C
 * EN v1.1 Size: 820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dll_7D_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* arg6);

/*
 * --INFO--
 *
 * Function: dll_7E_func03
 * EN v1.0 Address: 0x800F4FA4
 * EN v1.0 Size: 820b
 * EN v1.1 Address: 0x800F5240
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7E_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* arg6 );

/*
 * --INFO--
 *
 * Function: dll_7F_func03
 * EN v1.0 Address: 0x800F52E0
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x800F557C
 * EN v1.1 Size: 1272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7F_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_80_func03
 * EN v1.0 Address: 0x800F57D8
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x800F5A74
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_80_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_81_func03
 * EN v1.0 Address: 0x800F5A8C
 * EN v1.0 Size: 1724b
 * EN v1.1 Address: 0x800F5D28
 * EN v1.1 Size: 1732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_81_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_82_func03
 * EN v1.0 Address: 0x800F6150
 * EN v1.0 Size: 988b
 * EN v1.1 Address: 0x800F63EC
 * EN v1.1 Size: 996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_82_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_83_func03
 * EN v1.0 Address: 0x800F6534
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F67D0
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_83_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_84_func03
 * EN v1.0 Address: 0x800F6988
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F6C24
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_84_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315CA8;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x9;
    e[0].tex = base + 0x1c8;
    e[0].mode = 0x2;
    e[0].x = lbl_803E0F20;
    e[0].y = lbl_803E0F24;
    e[0].z = lbl_803E0F20;
    e[1].layer = 0;
    e[1].flags = 0x9;
    e[1].tex = base + 0x1dc;
    e[1].mode = 0x2;
    e[1].x = lbl_803E0F28;
    e[1].y = lbl_803E0F24;
    e[1].z = lbl_803E0F28;
    e[2].layer = 0;
    e[2].flags = 0x9;
    e[2].tex = base + 0x1f0;
    e[2].mode = 0x2;
    e[2].x = lbl_803E0F28;
    e[2].y = lbl_803E0F24;
    e[2].z = lbl_803E0F28;
    e[3].layer = 0;
    e[3].flags = 0x9;
    e[3].tex = base + 0x204;
    e[3].mode = 0x2;
    e[3].x = lbl_803E0F28;
    e[3].y = lbl_803E0F24;
    e[3].z = lbl_803E0F28;
    e[4].layer = 0;
    e[4].flags = 0x24;
    e[4].tex = base + 0x260;
    e[4].mode = 0x4;
    e[4].x = lbl_803E0F2C;
    e[4].y = lbl_803E0F2C;
    e[4].z = lbl_803E0F2C;
    e[5].layer = 0;
    e[5].flags = 0x0;
    e[5].tex = (void*)0;
    e[5].mode = 0x400000;
    e[5].x = lbl_803E0F30;
    e[5].y = lbl_803E0F34;
    e[5].z = lbl_803E0F38;
    e[6].layer = 1;
    e[6].flags = 0x24;
    e[6].tex = base + 0x260;
    e[6].mode = 0x2;
    e[6].x = lbl_803E0F3C;
    e[6].y = lbl_803E0F40;
    e[6].z = lbl_803E0F3C;
    e[7].layer = 1;
    e[7].flags = 0x24;
    e[7].tex = base + 0x260;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0F2C;
    e[7].y = lbl_803E0F2C;
    e[7].z = lbl_803E0F2C;
    e[8].layer = 1;
    e[8].flags = 0x24;
    e[8].tex = base + 0x260;
    e[8].mode = 0x100;
    e[8].x = lbl_803E0F2C;
    e[8].y = lbl_803E0F2C;
    e[8].z = lbl_803E0F44;
    e[9].layer = 2;
    e[9].flags = 0x12;
    e[9].tex = base + 0x2a8;
    e[9].mode = 0x4;
    e[9].x = lbl_803E0F48;
    e[9].y = lbl_803E0F2C;
    e[9].z = lbl_803E0F2C;
    e[10].layer = 2;
    e[10].flags = 0x24;
    e[10].tex = base + 0x260;
    e[10].mode = 0x2;
    e[10].x = lbl_803E0F4C;
    e[10].y = lbl_803E0F50;
    e[10].z = lbl_803E0F4C;
    e[11].layer = 2;
    e[11].flags = 0x24;
    e[11].tex = base + 0x260;
    e[11].mode = 0x4000;
    e[11].x = lbl_803E0F2C;
    e[11].y = lbl_803E0F2C;
    e[11].z = lbl_803E0F2C;
    e[12].layer = 2;
    e[12].flags = 0x0;
    e[12].tex = (void*)0;
    e[12].mode = 0x400000;
    e[12].x = lbl_803E0F54;
    e[12].y = lbl_803E0F58;
    e[12].z = lbl_803E0F5C;
    e[13].layer = 2;
    e[13].flags = 0x24;
    e[13].tex = base + 0x260;
    e[13].mode = 0x100;
    e[13].x = lbl_803E0F2C;
    e[13].y = lbl_803E0F2C;
    e[13].z = lbl_803E0F44;
    e[14].layer = 3;
    e[14].flags = 0x24;
    e[14].tex = base + 0x260;
    e[14].mode = 0x100;
    e[14].x = lbl_803E0F2C;
    e[14].y = lbl_803E0F2C;
    e[14].z = lbl_803E0F44;
    e[15].layer = 3;
    e[15].flags = 0x24;
    e[15].tex = base + 0x260;
    e[15].y = lbl_803E0F2C;
    e[15].x = lbl_803E0F2C;
    e[15].y = lbl_803E0F60;
    e[15].z = lbl_803E0F2C;
    e[16].layer = 4;
    e[16].flags = 0x24;
    e[16].tex = base + 0x260;
    e[16].y = lbl_803E0F2C;
    e[16].x = lbl_803E0F2C;
    e[16].y = lbl_803E0F60;
    e[16].z = lbl_803E0F2C;
    e[17].layer = 4;
    e[17].flags = 0x24;
    e[17].tex = base + 0x260;
    e[17].mode = 0x100;
    e[17].x = lbl_803E0F2C;
    e[17].y = lbl_803E0F2C;
    e[17].z = lbl_803E0F64;
    e[18].layer = 4;
    e[18].flags = 0x12;
    e[18].tex = base + 0x2a8;
    e[18].mode = 0x4;
    e[18].x = lbl_803E0F2C;
    e[18].y = lbl_803E0F2C;
    e[18].z = lbl_803E0F2C;
    e[19].layer = 4;
    e[19].flags = 0x24;
    e[19].tex = base + 0x260;
    e[19].mode = 0x2;
    e[19].x = lbl_803E0F68;
    e[19].y = lbl_803E0F6C;
    e[19].z = lbl_803E0F68;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E0F2C;
    buf.pos[1] = lbl_803E0F2C;
    buf.pos[2] = lbl_803E0F2C;
    buf.col[0] = lbl_803E0F2C;
    buf.col[1] = lbl_803E0F2C;
    buf.col[2] = lbl_803E0F2C;
    buf.scale = lbl_803E0F6C;
    buf.v40 = 3;
    buf.v3c = 9;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x4000484;
    buf.count = (FbCmd*)((u8*)e + 0x1e0) - e;
    buf.hw[0] = *(s16*)(base + 0x2cc);
    buf.hw[1] = *(s16*)(base + 0x2ce);
    buf.hw[2] = *(s16*)(base + 0x2d0);
    buf.hw[3] = *(s16*)(base + 0x2d2);
    buf.hw[4] = *(s16*)(base + 0x2d4);
    buf.hw[5] = *(s16*)(base + 0x2d6);
    buf.hw[6] = *(s16*)(base + 0x2d8);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0F2C + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0F2C + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0F2C + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0F2C + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E0F2C + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E0F2C + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x24, (u8*)(int)lbl_80315CA8, 0x10, base + 0x168, 0x3f, 0);
}

/*
 * --INFO--
 *
 * Function: dll_85_func03
 * EN v1.0 Address: 0x800F6DDC
 * EN v1.0 Size: 1616b
 * EN v1.1 Address: 0x800F7078
 * EN v1.1 Size: 1624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_85_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_86_func03
 * EN v1.0 Address: 0x800F7434
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x800F76D0
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_86_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_87_func03
 * EN v1.0 Address: 0x800F77BC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F7A58
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_87_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_88_func03
 * EN v1.0 Address: 0x800F7AC0
 * EN v1.0 Size: 712b
 * EN v1.1 Address: 0x800F7D5C
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_88_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_89_func03
 * EN v1.0 Address: 0x800F7D90
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F802C
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_89_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_8A_func03
 * EN v1.0 Address: 0x800F8094
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x800F8330
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8A_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_8B_func03
 * EN v1.0 Address: 0x800F8250
 * EN v1.0 Size: 1424b
 * EN v1.1 Address: 0x800F84EC
 * EN v1.1 Size: 1432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8B_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* arg6);

/*
 * --INFO--
 *
 * Function: dll_8C_func03
 * EN v1.0 Address: 0x800F87E8
 * EN v1.0 Size: 1400b
 * EN v1.1 Address: 0x800F8A84
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8C_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_8D_func03
 * EN v1.0 Address: 0x800F8D68
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800F9004
 * EN v1.1 Size: 2580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dll_8D_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_8E_func03
 * EN v1.0 Address: 0x800F977C
 * EN v1.0 Size: 1780b
 * EN v1.1 Address: 0x800F9A18
 * EN v1.1 Size: 1788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8E_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_8F_func03
 * EN v1.0 Address: 0x800F9E78
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x800FA114
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8F_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_90_func03
 * EN v1.0 Address: 0x800FA16C
 * EN v1.0 Size: 1124b
 * EN v1.1 Address: 0x800FA408
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_90_func03(int sourceObj, int variant, int posSource, uint flags);


/* Trivial 4b 0-arg blr leaves. */
void dll_7C_func01_nop(void);

void dll_7C_func00_nop(void);

void dll_7D_func01_nop(void);

void dll_7D_func00_nop(void);

void dll_7E_func01_nop(void);

void dll_7E_func00_nop(void);

void dll_7F_func01_nop(void);

void dll_7F_func00_nop(void);

void dll_80_func01_nop(void);

void dll_80_func00_nop(void);

void dll_81_func01_nop(void);

void dll_81_func00_nop(void);

void dll_82_func01_nop(void);

void dll_82_func00_nop(void);

void dll_83_func01_nop(void);

void dll_83_func00_nop(void);

void dll_84_func01_nop(void)
{
}

void dll_84_func00_nop(void)
{
}

void dll_85_func01_nop(void);

void dll_85_func00_nop(void);

void dll_86_func01_nop(void);

void dll_86_func00_nop(void);

void dll_87_func01_nop(void);

void dll_87_func00_nop(void);

void dll_88_func01_nop(void);

void dll_88_func00_nop(void);

void dll_89_func01_nop(void);

void dll_89_func00_nop(void);

void dll_8A_func01_nop(void);

void dll_8A_func00_nop(void);

void dll_8B_func01_nop(void);

void dll_8B_func00_nop(void);

void dll_8C_func01_nop(void);

void dll_8C_func00_nop(void);

void dll_8D_func01_nop(void);

void dll_8D_func00_nop(void);

void dll_8E_func01_nop(void);

void dll_8E_func00_nop(void);

void dll_8F_func01_nop(void);

void dll_8F_func00_nop(void);

void dll_90_func01_nop(void);

void dll_90_func00_nop(void);
