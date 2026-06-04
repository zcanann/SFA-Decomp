#include "ghidra_import.h"
#include "main/shader.h"


#pragma peephole off
#pragma scheduling off
extern float ABS();
extern undefined4 FUN_800033a8();
extern undefined8 FUN_80006724();
extern undefined4 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800068b8();
extern undefined4 FUN_800068d8();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_8000693c();
extern undefined4 FUN_80006958();
extern undefined4 FUN_8000696c();
extern void* FUN_800069a8();
extern undefined8 FUN_80006a88();
extern undefined4 FUN_80006adc();
extern undefined8 FUN_80006c1c();
extern undefined4 FUN_80006c28();
extern undefined4 FUN_80017488();
extern undefined8 FUN_800174b8();
extern undefined8 FUN_80017630();
extern undefined8 FUN_80017640();
extern undefined8 FUN_80017644();
extern undefined4 FUN_800176a8();
extern undefined4 FUN_8001771c();
extern undefined8 FUN_80017810();
extern undefined8 FUN_80017814();
extern undefined4 FUN_80017830();
extern undefined4 FUN_800178bc();
extern int FUN_80017a98();
extern undefined4 FUN_80017aa0();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern int FUN_80017b00();
extern undefined4 FUN_80017b10();
extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80040d88();
extern undefined8 FUN_80040d94();
extern int FUN_80042830();
extern int FUN_80042838();
extern undefined4 FUN_80042f88();
extern int mapLoadDataFile();
extern undefined8 FUN_800443fc();
extern int FUN_80044404();
extern undefined8 FUN_80044424();
extern undefined4 piRomLoadSection();
extern undefined8 FUN_80044f74();
extern uint FUN_800452f8();
extern undefined8 FUN_80045328();
extern undefined4 FUN_80045c4c();
extern undefined8 FUN_8004600c();
extern undefined4 FUN_80053754();
extern undefined4 FUN_80053758();
extern undefined4 FUN_80053c9c();
extern uint FUN_80053f60();
extern undefined4 FUN_800600f4();
extern undefined8 FUN_800601e4();
extern undefined4 FUN_800602d4();
extern undefined4 FUN_800604ac();
extern undefined4 FUN_8006069c();
extern undefined4 FUN_800614d0();
extern undefined8 FUN_800627a0();
extern undefined4 FUN_800632cc();
extern void trackDolphin_initIntersectionBuffers(void);
extern undefined8 FUN_8006f564();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern int FUN_800e83c8();
extern int FUN_800e87a0();
extern void* FUN_800e87a8();
extern undefined4 FUN_800e8b48();
extern undefined4 FUN_800e8b54();
extern int FUN_800e9b14();
extern undefined8 FUN_800e9c00();
extern undefined4 FUN_80130150();
extern undefined4 FUN_8013028c();
extern undefined4 FUN_80130298();
extern undefined4 FUN_80132550();
extern undefined4 FUN_80135814();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern double FUN_80247f90();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined4 FUN_8028682c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();

extern undefined4 DAT_802c25d8;
extern undefined4 DAT_802c25dc;
extern undefined4 DAT_802c25e0;
extern undefined4 DAT_802c25e4;
extern undefined4 DAT_802c25e8;
extern undefined4 DAT_802c25ec;
extern undefined4 DAT_802c25f0;
extern undefined4 DAT_802c25f4;
extern undefined4 DAT_802c25f8;
extern undefined4 DAT_802c25fc;
extern undefined4 DAT_802c2600;
extern undefined4 DAT_802c2604;
extern undefined4 DAT_802c2608;
extern undefined4 DAT_802c260c;
extern undefined4 DAT_802c2610;
extern undefined4 DAT_802c2614;
extern undefined4 DAT_802c2618;
extern undefined4 DAT_802c261c;
extern undefined4 DAT_802c2620;
extern undefined4 DAT_802c2624;
extern undefined4 DAT_8030f11c;
extern undefined4 DAT_8030f194;
extern undefined4 DAT_80382e98;
extern short* DAT_80382e9c;
extern undefined4 DAT_80382ea0;
extern char* DAT_80382ea4;
extern undefined4 DAT_80382ea8;
extern int DAT_80382eac;
extern undefined4 DAT_80382eb0;
extern undefined4 DAT_80382eb2;
extern int DAT_80382eec;
extern int DAT_80382f00;
extern int DAT_80382f14;
extern undefined4 DAT_80382fb0;
extern uint DAT_803870c8;
extern int DAT_80387208;
extern undefined4 DAT_803872a8;
extern undefined4 DAT_803872ac;
extern undefined4 DAT_803872b0;
extern undefined4 DAT_803872b4;
extern undefined4 DAT_803872c4;
extern undefined4 DAT_803872d4;
extern undefined4 DAT_803872e4;
extern undefined4 DAT_803872f4;
extern undefined4 DAT_80387304;
extern undefined4 DAT_80387314;
extern undefined4 DAT_80387324;
extern undefined4 DAT_80387334;
extern undefined4 DAT_80387344;
extern undefined4 DAT_80387354;
extern undefined4 DAT_80387364;
extern undefined4 DAT_80387374;
extern undefined4 DAT_80387384;
extern undefined4 DAT_80387394;
extern undefined4 DAT_803873a4;
extern undefined4 DAT_803873b4;
extern undefined4 DAT_803873c4;
extern undefined4 DAT_803873d4;
extern undefined4 DAT_803873e4;
extern undefined4 DAT_803873f4;
extern undefined4 DAT_80387404;
extern undefined4 DAT_80387414;
extern undefined4 DAT_80387424;
extern undefined4 DAT_80387434;
extern undefined4 DAT_80387444;
extern undefined4 DAT_80387454;
extern undefined4 DAT_80387464;
extern undefined4 DAT_80387474;
extern undefined4 DAT_80387484;
extern undefined4 DAT_80388538;
extern undefined4 DAT_8038859c;
extern undefined4 DAT_803885a0;
extern undefined4 DAT_803885a4;
extern undefined4 DAT_803885a8;
extern undefined4 DAT_803dc280;
extern undefined4 DAT_803dc284;
extern undefined4 DAT_803dc2a8;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6dc;
extern undefined4* DAT_803dd6e0;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd6ec;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd700;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803dda48;
extern undefined4 DAT_803dda4c;
extern undefined4 DAT_803dda50;
extern undefined4 DAT_803dda54;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803dda61;
extern int* DAT_803dda64;
extern undefined4 DAT_803dda68;
extern undefined4 DAT_803dda6c;
extern undefined4 DAT_803dda6d;
extern undefined4 DAT_803dda74;
extern undefined4 DAT_803dda77;
extern undefined4 DAT_803dda80;
extern undefined4 DAT_803dda84;
extern undefined4 DAT_803dda9c;
extern undefined4 DAT_803ddae8;
extern int* DAT_803ddaec;
extern undefined4 DAT_803ddaf0;
extern undefined4 DAT_803ddaf4;
extern short* DAT_803ddaf8;
extern undefined4 DAT_803ddafc;
extern undefined4 DAT_803ddb04;
extern undefined4 DAT_803ddb08;
extern undefined4 DAT_803ddb0c;
extern undefined4 DAT_803ddb10;
extern short* DAT_803ddb14;
extern undefined4 DAT_803ddb18;
extern undefined4 DAT_803ddb1c;
extern undefined4 DAT_803ddb20;
extern undefined4 DAT_803ddb24;
extern undefined4 DAT_803ddb28;
extern undefined4 DAT_803ddb30;
extern undefined4 DAT_803ddb34;
extern undefined4 DAT_803ddb36;
extern undefined4 DAT_803ddb38;
extern undefined4 DAT_803ddb3d;
extern undefined4 DAT_803ddb40;
extern undefined4 DAT_803ddb44;
extern undefined4 DAT_803ddb48;
extern f64 DOUBLE_803df840;
extern f32 lbl_803DC28C;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDADC;
extern f32 lbl_803DDAE0;
extern f32 lbl_803DDAE4;
extern f32 lbl_803DDB4C;
extern f32 lbl_803DDB50;
extern f32 lbl_803DF834;
extern f32 lbl_803DF838;
extern f32 lbl_803DF848;
extern f32 lbl_803DF84C;
extern f32 lbl_803DF850;
extern f32 lbl_803DF854;
extern f32 lbl_803DF858;
extern f32 lbl_803DF85C;
extern f32 lbl_803DF860;
extern f32 lbl_803DF864;
extern f32 lbl_803DF868;
extern f32 lbl_803DF86C;
extern f32 lbl_803DF870;
extern f32 lbl_803DF874;
extern undefined cRam803dc285;
extern undefined2 cRam803dc286;
extern undefined cRam803dc287;
extern undefined4 cRam803dc288;

/*
 * --INFO--
 *
 * Function: objShouldLoad
 * EN v1.0 Address: 0x80055980
 * EN v1.0 Size: 908b
 * EN v1.1 Address: 0x80055AFC
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern char lbl_8030E4B0[];
extern int* gMapEventInterface;
extern int gMapBlockLayerTables[5];
extern u8 lbl_80386648[];
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 gMapBlockWorldSize;
extern f32 fastFloorf(f32 v);
extern int* Obj_GetPlayerObject(void);
extern void OSReport(const char* fmt, ...);

int objShouldLoad(int param_1,int param_2,int param_3)
{
    char* strs;
    int verbose;
    int useObj;
    f32 y;
    f32 z;
    f32 x;
    int t;
    int ok;
    int bx;
    int bz;
    s8 found;
    s8 i;
    int* tbl;
    int* player;
    int off;
    f32* p;
    f32 d;
    f32 dz;
    f32 dy;
    f32 range;

    strs = (char*)lbl_8030E4B0;
    if (*(u32*)(param_1 + 0x14) == 0x49054) {
        verbose = 1;
    } else {
        verbose = 0;
    }
    t = ((u8(*)(int)) * (int*)(*gMapEventInterface + 0x40))(param_3);
    if (t == -1) {
        ok = 0;
        goto test;
    }
    if (t != 0) {
        if (t < 9) {
            if ((*(u8*)(param_1 + 3) >> (t - 1)) & 1) {
                ok = 0;
                goto test;
            }
        } else {
            if ((*(u8*)(param_1 + 5) >> (16 - t)) & 1) {
                ok = 0;
                goto test;
            }
        }
    }
    ok = 1;
test:
    if (ok == 0) {
        return 0;
    }
    if (*(u8*)(param_1 + 4) & 1) {
        if (verbose) {
            OSReport(strs + 0x1cc);
        }
        return 1;
    }
    if (*(u8*)(param_1 + 4) & 2) {
        if (verbose) {
            OSReport(strs + 0x1e8);
        }
        return 0;
    }
    if ((s8)param_2 == 0) {
        bx = (int)fastFloorf((*(f32*)(param_1 + 8) - playerMapOffsetX) / gMapBlockWorldSize);
        bz = (int)fastFloorf((*(f32*)(param_1 + 0x10) - playerMapOffsetZ) / gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16) {
            if (verbose) {
                OSReport(strs + 0x200, param_1 + 8, param_1 + 0xc, param_1 + 0x10);
            }
            return 0;
        }
        found = 0;
        bx += bz << 4;
        for (i = 0; i < 5; i++) {
            if (*(s8*)(bx + gMapBlockLayerTables[i]) >= 0) {
                found = 1;
            }
        }
        if (found == 0) {
            if (verbose) {
                OSReport(strs + 0x228);
            }
            return 0;
        }
    }
    if (*(u8*)(param_1 + 4) & 0x20) {
        if (verbose) {
            OSReport(strs + 0x240);
        }
        return 1;
    }
    useObj = 0;
    if ((*(u8*)(param_1 + 4) & 4) && (s8)param_2 == 0) {
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            x = *(f32*)((char*)player + 0x18);
            y = *(f32*)((char*)player + 0x1c);
            z = *(f32*)((char*)player + 0x20);
        } else {
            useObj = 1;
        }
    } else {
        useObj = 1;
    }
    if (useObj != 0) {
        off = (s8)param_2 << 4;
        x = *(f32*)(lbl_80386648 + off);
        p = (f32*)(lbl_80386648 + off);
        y = p[1];
        z = p[2];
    }
    range = (f32)(*(u8*)(param_1 + 6) << 3);
    d = x - *(f32*)(param_1 + 8);
    dy = y - *(f32*)(param_1 + 0xc);
    dz = z - *(f32*)(param_1 + 0x10);
    d = d * d + dy * dy + dz * dz;
    if (d < range * range) {
        if (verbose) {
            OSReport(strs + 0x25c, &d);
        }
        return 1;
    }
    if (verbose) {
        OSReport(strs + 0x274);
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80055d0c
 * EN v1.0 Address: 0x80055D0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80055EA0
 * EN v1.1 Size: 1912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055d0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80055d10
 * EN v1.0 Address: 0x80055D10
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x80056618
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055d10(void)
{
  int iVar1;
  int *piVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  float local_28;
  float local_24;
  float local_20;
  int local_1c [7];
  
  FUN_80286840();
  piVar2 = ObjGroup_GetObjects(6,local_1c);
  psVar3 = FUN_800069a8();
  FUN_800068d8(psVar3);
  DAT_803872c4 = 0;
  DAT_803872d4 = 0;
  DAT_803872e4 = 0;
  DAT_803872f4 = 0;
  DAT_80387304 = 0;
  DAT_80387314 = 0;
  DAT_80387324 = 0;
  DAT_80387334 = 0;
  DAT_80387344 = 0;
  DAT_80387354 = 0;
  DAT_80387364 = 0;
  DAT_80387374 = 0;
  DAT_80387384 = 0;
  DAT_80387394 = 0;
  DAT_803873a4 = 0;
  DAT_803873b4 = 0;
  DAT_803873c4 = 0;
  DAT_803873d4 = 0;
  DAT_803873e4 = 0;
  DAT_803873f4 = 0;
  DAT_80387404 = 0;
  DAT_80387414 = 0;
  DAT_80387424 = 0;
  DAT_80387434 = 0;
  DAT_80387444 = 0;
  DAT_80387454 = 0;
  DAT_80387464 = 0;
  DAT_80387474 = 0;
  DAT_80387484 = 0;
  iVar4 = -0x7fc78b78;
  iVar1 = 1;
  do {
    *(undefined4 *)(iVar4 + 0xc) = 0;
    iVar4 = iVar4 + 0x10;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  DAT_803872a8 = *(undefined4 *)(psVar3 + 0x22);
  DAT_803872ac = *(undefined4 *)(psVar3 + 0x24);
  DAT_803872b0 = *(undefined4 *)(psVar3 + 0x26);
  DAT_803872b4 = 1;
  for (iVar1 = 0; iVar1 < local_1c[0]; iVar1 = iVar1 + 1) {
    iVar4 = *piVar2;
    iVar5 = *(char *)(iVar4 + 0x35) + 1;
    if (*(int *)(psVar3 + 0x20) == iVar4) {
      (&DAT_803872a8)[iVar5 * 4] = *(undefined4 *)(psVar3 + 6);
      (&DAT_803872ac)[iVar5 * 4] = *(undefined4 *)(psVar3 + 8);
      (&DAT_803872b0)[iVar5 * 4] = *(undefined4 *)(psVar3 + 10);
    }
    else {
      FUN_800068f4((double)*(float *)(psVar3 + 0x22),(double)*(float *)(psVar3 + 0x24),
                   (double)*(float *)(psVar3 + 0x26),&local_20,&local_24,&local_28,iVar4);
      (&DAT_803872a8)[iVar5 * 4] = local_20;
      (&DAT_803872ac)[iVar5 * 4] = local_24;
      (&DAT_803872b0)[iVar5 * 4] = local_28;
    }
    (&DAT_803872b4)[iVar5 * 4] = 1;
    piVar2 = piVar2 + 1;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: fn_80056800
 * EN v1.0 Address: 0x80055ED8
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80056800
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_80056800(int param_1)
{
  return (int)(DAT_803ddaec + param_1 * 4);
}

/*
 * --INFO--
 *
 * Function: FUN_80055ee8
 * EN v1.0 Address: 0x80055EE8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80056810
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80055ee8(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80055ef0
 * EN v1.0 Address: 0x80055EF0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80056818
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80055ef0(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80055ef8
 * EN v1.0 Address: 0x80055EF8
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80056820
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80055ef8(int param_1,uint param_2)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = 0;
  iVar4 = 0x28;
  do {
    piVar1 = (int *)(DAT_803ddaec + iVar2);
    if (((*piVar1 == param_1) && (param_2 == *(byte *)((int)piVar1 + 0xe))) &&
       (0 < *(short *)(piVar1 + 3))) {
      *(short *)(piVar1 + 3) = *(short *)(piVar1 + 3) + -1;
      if (*(short *)(DAT_803ddaec + iVar2 + 0xc) == 0) {
        *(undefined4 *)(DAT_803ddaec + iVar2 + 4) = 0;
        *(undefined *)(DAT_803ddaec + iVar2 + 0xe) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar2) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar2 + 8) = 0;
      }
    }
    iVar3 = iVar2 + 0x10;
    piVar1 = (int *)(DAT_803ddaec + iVar3);
    if (((*piVar1 == param_1) && (param_2 == *(byte *)((int)piVar1 + 0xe))) &&
       (0 < *(short *)(piVar1 + 3))) {
      *(short *)(piVar1 + 3) = *(short *)(piVar1 + 3) + -1;
      if (*(short *)(DAT_803ddaec + iVar3 + 0xc) == 0) {
        *(undefined4 *)(DAT_803ddaec + iVar3 + 4) = 0;
        *(undefined *)(DAT_803ddaec + iVar2 + 0x1e) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar3) = 0;
        *(undefined4 *)(DAT_803ddaec + iVar2 + 0x18) = 0;
      }
    }
    iVar2 = iVar2 + 0x20;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056000
 * EN v1.0 Address: 0x80056000
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x80056924
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056000(int param_1,int param_2,uint param_3)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  iVar4 = 0x10;
  piVar2 = DAT_803ddaec;
  do {
    if ((((*(short *)(piVar2 + 3) != 0) && (*piVar2 == param_1)) &&
        (iVar1 = iVar3, param_3 == *(byte *)((int)piVar2 + 0xe))) ||
       ((((((iVar1 = iVar3 + 1, *(short *)(piVar2 + 7) != 0 && (piVar2[4] == param_1)) &&
           (param_3 == *(byte *)((int)piVar2 + 0x1e))) ||
          (((iVar1 = iVar3 + 2, *(short *)(piVar2 + 0xb) != 0 && (piVar2[8] == param_1)) &&
           (param_3 == *(byte *)((int)piVar2 + 0x2e))))) ||
         (((iVar1 = iVar3 + 3, *(short *)(piVar2 + 0xf) != 0 && (piVar2[0xc] == param_1)) &&
          (param_3 == *(byte *)((int)piVar2 + 0x3e))))) ||
        (((*(short *)(piVar2 + 0x13) != 0 && (piVar2[0x10] == param_1)) &&
         (iVar1 = iVar3 + 4, param_3 == *(byte *)((int)piVar2 + 0x4e))))))) break;
    piVar2 = piVar2 + 0x14;
    iVar3 = iVar3 + 5;
    iVar4 = iVar4 + -1;
    iVar1 = -1;
  } while (iVar4 != 0);
  if (iVar1 == -1) {
    iVar3 = 0;
    iVar4 = 8;
    piVar2 = DAT_803ddaec;
    do {
      iVar1 = iVar3;
      if (((((*(short *)(piVar2 + 3) == 0) || (iVar1 = iVar3 + 1, *(short *)(piVar2 + 7) == 0)) ||
           ((iVar1 = iVar3 + 2, *(short *)(piVar2 + 0xb) == 0 ||
            ((((iVar1 = iVar3 + 3, *(short *)(piVar2 + 0xf) == 0 ||
               (iVar1 = iVar3 + 4, *(short *)(piVar2 + 0x13) == 0)) ||
              (iVar1 = iVar3 + 5, *(short *)(piVar2 + 0x17) == 0)) ||
             ((iVar1 = iVar3 + 6, *(short *)(piVar2 + 0x1b) == 0 ||
              (iVar1 = iVar3 + 7, *(short *)(piVar2 + 0x1f) == 0)))))))) ||
          (iVar1 = iVar3 + 8, *(short *)(piVar2 + 0x23) == 0)) ||
         (iVar1 = iVar3 + 9, *(short *)(piVar2 + 0x27) == 0)) break;
      piVar2 = piVar2 + 0x28;
      iVar3 = iVar3 + 10;
      iVar4 = iVar4 + -1;
      iVar1 = -1;
    } while (iVar4 != 0);
    if (iVar1 == -1) {
      FUN_800723a0();
      iVar1 = 0;
    }
    else {
      *(undefined2 *)(DAT_803ddaec + iVar1 * 4 + 3) = 1;
      DAT_803ddaec[iVar1 * 4 + 1] = 0;
      DAT_803ddaec[iVar1 * 4 + 2] = param_2;
      DAT_803ddaec[iVar1 * 4] = param_1;
      *(char *)((int)DAT_803ddaec + iVar1 * 0x10 + 0xe) = (char)param_3;
    }
  }
  else {
    *(short *)(DAT_803ddaec + iVar1 * 4 + 3) = *(short *)(DAT_803ddaec + iVar1 * 4 + 3) + 1;
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800562d0
 * EN v1.0 Address: 0x800562D0
 * EN v1.0 Size: 280b
 * EN v1.1 Address: 0x80056BE8
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800562d0(uint param_1,int param_2,int param_3)
{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar1 = 0;
  iVar3 = 0x10;
  do {
    piVar2 = (int *)(DAT_803ddaec + iVar1);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x10);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x20);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x30);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    piVar2 = (int *)(DAT_803ddaec + iVar1 + 0x40);
    if (((0 < *(short *)(piVar2 + 3)) && (*piVar2 == param_2)) &&
       (param_1 == *(byte *)((int)piVar2 + 0xe))) {
      piVar2[1] = param_3;
    }
    iVar1 = iVar1 + 0x50;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800563e8
 * EN v1.0 Address: 0x800563E8
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80056D08
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800563e8(int param_1,float *param_2,float *param_3)
{
  float fVar1;
  
  fVar1 = lbl_803DF848;
  *param_2 = *(float *)(DAT_803ddae8 + param_1 * 0x10) / lbl_803DF848;
  *param_3 = *(float *)(DAT_803ddae8 + param_1 * 0x10 + 4) / fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056418
 * EN v1.0 Address: 0x80056418
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x80056D38
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056418(int param_1,int param_2,int param_3,int param_4,int param_5)
{
  int iVar1;
  
  iVar1 = DAT_803ddae8 + param_1 * 0x10;
  *(short *)(iVar1 + 8) = (short)((param_2 << 0x10) / (param_4 >> 6));
  *(short *)(iVar1 + 10) = (short)((param_3 << 0x10) / (param_5 >> 6));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056448
 * EN v1.0 Address: 0x80056448
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x80056D70
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056448(int param_1,int param_2,int param_3,int param_4)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  iVar6 = 0x3a;
  iVar2 = DAT_803ddae8;
  do {
    if ((*(short *)(iVar2 + 8) == param_1) && (*(short *)(iVar2 + 10) == param_2)) {
      *(char *)(iVar2 + 0xc) = *(char *)(iVar2 + 0xc) + '\x01';
      return iVar4;
    }
    iVar2 = iVar2 + 0x10;
    iVar4 = iVar4 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  iVar4 = 0;
  iVar6 = 0x1d;
  iVar2 = DAT_803ddae8;
  do {
    iVar5 = iVar4;
    if ((*(char *)(iVar2 + 0xc) == '\0') || (iVar5 = iVar4 + 1, *(char *)(iVar2 + 0x1c) == '\0'))
    break;
    iVar2 = iVar2 + 0x20;
    iVar4 = iVar4 + 2;
    iVar6 = iVar6 + -1;
    iVar5 = -1;
  } while (iVar6 != 0);
  if (iVar5 != -1) {
    pfVar3 = (float *)(DAT_803ddae8 + iVar5 * 0x10);
    *(short *)(pfVar3 + 2) = (short)((param_1 << 0x10) / (param_3 >> 6));
    *(short *)((int)pfVar3 + 10) = (short)((param_2 << 0x10) / (param_4 >> 6));
    fVar1 = lbl_803DF84C;
    *pfVar3 = lbl_803DF84C;
    pfVar3[1] = fVar1;
    *(char *)(pfVar3 + 3) = *(char *)(pfVar3 + 3) + '\x01';
    return iVar5;
  }
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_8005652c
 * EN v1.0 Address: 0x8005652C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x80056E68
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005652c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)
{
  undefined4 uVar1;
  short *psVar2;
  short extraout_r4;
  uint uVar3;
  uint uVar4;
  
  uVar1 = FUN_80286840();
  uVar3 = 0;
  uVar4 = (uint)DAT_803ddb18;
  for (psVar2 = DAT_803ddb14; (uVar4 != 0 && (*psVar2 != -1)); psVar2 = psVar2 + 1) {
    uVar3 = uVar3 + 1;
    uVar4 = uVar4 - 1;
  }
  if ((uVar3 == DAT_803ddb18) && (DAT_803ddb18 = DAT_803ddb18 + 1, DAT_803ddb18 == 0x40)) {
    FUN_800723a0();
  }
  *(char *)((&DAT_80382f14)[param_4] + param_3) = (char)uVar3;
  *(undefined4 *)(DAT_803ddb1c + uVar3 * 4) = uVar1;
  DAT_803ddb14[uVar3] = extraout_r4;
  *(undefined *)(DAT_803ddb0c + uVar3) = 1;
  FUN_800632cc();
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800565f8
 * EN v1.0 Address: 0x800565F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80056F48
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800565f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 int param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800565fc
 * EN v1.0 Address: 0x800565FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800570F8
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800565fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056600
 * EN v1.0 Address: 0x80056600
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80057360
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056600(void)
{
  return (int)DAT_803dda61;
}

/*
 * --INFO--
 *
 * Function: FUN_80056608
 * EN v1.0 Address: 0x80056608
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8005736C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056608(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)
{
  if (((DAT_803ddb48 != -1) &&
      (((DAT_803ddb48 != DAT_803ddb44 || (param_9 != '\0')) &&
       (DAT_803ddb44 = DAT_803ddb48, DAT_803ddb48 < 0x76)))) &&
     ((char)(&DAT_8030f11c)[DAT_803ddb48] != -1)) {
    FUN_80017488(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(char)(&DAT_8030f11c)[DAT_803ddb48]);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800566c8
 * EN v1.0 Address: 0x800566C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800573D4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800566cc
 * EN v1.0 Address: 0x800566CC
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8005756C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566cc(void)
{
  DAT_803ddb24 = 0;
  DAT_803ddb36 = 0;
  DAT_803ddb34 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800566e0
 * EN v1.0 Address: 0x800566E0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80057580
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800566e0(void)
{
  return (int)DAT_803ddb24;
}

/*
 * --INFO--
 *
 * Function: FUN_800566e8
 * EN v1.0 Address: 0x800566E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8005758C
 * EN v1.1 Size: 2324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800566ec
 * EN v1.0 Address: 0x800566EC
 * EN v1.0 Size: 776b
 * EN v1.1 Address: 0x80057EA0
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800566ec(int param_1,int param_2,int *param_3,int *param_4,int *param_5,int *param_6,
                 int param_7,int param_8,int param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  short *psVar5;
  short *psVar6;
  
  if (param_9 != -1) {
    psVar5 = (short *)(DAT_80382e9c + (short)(&DAT_80382eb0)[param_9 * 4] * 10);
    psVar6 = (short *)(&DAT_80382eac)[param_9 * 2];
    if (param_9 != -1) {
      if (param_8 == 0) {
        iVar2 = *(int *)(psVar6 + 10);
        iVar3 = *(int *)(psVar6 + 0x16);
      }
      else {
        iVar2 = *(int *)(psVar6 + 0x18);
        iVar3 = *(int *)(psVar6 + 0x1a);
      }
      uVar1 = (param_1 - *psVar5) + (param_2 - psVar5[2]) * (int)*psVar6;
      if (param_7 == 0) {
        uVar4 = *(uint *)(iVar2 + uVar1 * 8);
        *param_3 = (uVar4 >> 0xc & 0xf) - 7;
        param_3[2] = (uVar4 >> 8 & 0xf) - 7;
        param_3[1] = (uVar4 >> 4 & 0xf) - 7;
        param_3[3] = (uVar4 & 0xf) - 7;
        *param_4 = (uVar4 >> 0x1c) - 7;
        param_4[2] = (uVar4 >> 0x18 & 0xf) - 7;
        param_4[1] = (uVar4 >> 0x14 & 0xf) - 7;
        param_4[3] = (uVar4 >> 0x10 & 0xf) - 7;
        uVar1 = *(uint *)(iVar2 + uVar1 * 8 + 4);
        *param_5 = (uVar1 >> 0xc & 0xf) - 7;
        param_5[2] = (uVar1 >> 8 & 0xf) - 7;
        param_5[1] = (uVar1 >> 4 & 0xf) - 7;
        param_5[3] = (uVar1 & 0xf) - 7;
        *param_6 = (uVar1 >> 0x1c) - 7;
        param_6[2] = (uVar1 >> 0x18 & 0xf) - 7;
        param_6[1] = (uVar1 >> 0x14 & 0xf) - 7;
        param_6[3] = (uVar1 >> 0x10 & 0xf) - 7;
      }
      else {
        *param_3 = 0;
        param_3[1] = -1;
        param_3[2] = 0;
        param_3[3] = -1;
        *param_4 = 0;
        param_4[1] = -1;
        param_4[2] = 0;
        param_4[3] = -1;
        *param_5 = 0;
        param_5[1] = -1;
        param_5[2] = 0;
        param_5[3] = -1;
        *param_6 = 0;
        param_6[1] = -1;
        param_6[2] = 0;
        param_6[3] = -1;
        uVar1 = *(uint *)(*(int *)(psVar6 + 6) + ((int)(uVar1 * 2 | uVar1 >> 0x1f) >> 1) * 4) & 0x7f
        ;
        if (uVar1 != 0x7f) {
          uVar1 = *(uint *)(iVar3 + (param_7 + uVar1 * 4 + -1) * 4);
          *param_3 = (uVar1 >> 0xc & 0xf) - 7;
          param_3[2] = (uVar1 >> 8 & 0xf) - 7;
          param_3[1] = (uVar1 >> 4 & 0xf) - 7;
          param_3[3] = (uVar1 & 0xf) - 7;
          *param_4 = (uVar1 >> 0x1c) - 7;
          param_4[2] = (uVar1 >> 0x18 & 0xf) - 7;
          param_4[1] = (uVar1 >> 0x14 & 0xf) - 7;
          param_4[3] = (uVar1 >> 0x10 & 0xf) - 7;
        }
      }
    }
    else {
      *param_3 = -1;
      param_3[1] = 1;
      param_3[2] = -1;
      param_3[3] = 1;
      *param_4 = 0;
      param_4[1] = 0;
      param_4[2] = 0;
      param_4[3] = -1;
      *param_5 = 0;
      param_5[1] = 0;
      param_5[2] = 0;
      param_5[3] = -1;
      *param_6 = 0;
      param_6[1] = 0;
      param_6[2] = 0;
      param_6[3] = -1;
      if (param_7 != 0) {
        param_3[3] = -2;
      }
    }
  }
  else {
    *param_3 = -1;
    param_3[1] = 1;
    param_3[2] = -1;
    param_3[3] = 1;
    *param_4 = 0;
    param_4[1] = 0;
    param_4[2] = 0;
    param_4[3] = -1;
    *param_5 = 0;
    param_5[1] = 0;
    param_5[2] = 0;
    param_5[3] = -1;
    *param_6 = 0;
    param_6[1] = 0;
    param_6[2] = 0;
    param_6[3] = -1;
    if (param_7 != 0) {
      param_3[3] = -2;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800569f4
 * EN v1.0 Address: 0x800569F4
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x800581A8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800569f4(void)
{
  DAT_803dda61 = DAT_803dda61 + -1;
  if (DAT_803dda61 < -2) {
    DAT_803dda61 = -2;
  }
  DAT_803dda68 = DAT_803dda68 | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056a20
 * EN v1.0 Address: 0x80056A20
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x800581DC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a20(void)
{
  DAT_803dda61 = DAT_803dda61 + '\x01';
  if ('\x02' < DAT_803dda61) {
    DAT_803dda61 = '\x02';
  }
  DAT_803dda68 = DAT_803dda68 | 0x4000;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056a4c
 * EN v1.0 Address: 0x80056A4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80058210
 * EN v1.1 Size: 3144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056a50
 * EN v1.0 Address: 0x80056A50
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80058E58
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a50(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  uint uVar2;
  
  if (((DAT_803dda68 & 2) == 0) || ((DAT_803dda68 & 0x800) != 0)) {
    lbl_803DDAE4 = (float)param_1;
    lbl_803DDAE0 = (float)param_2;
    lbl_803DDADC = (float)param_3;
    uVar2 = DAT_803dda68 | 2;
    uVar1 = DAT_803dda68 & 0x800;
    DAT_803dda68 = uVar2;
    if (uVar1 != 0) {
      FUN_80056a4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056a88
 * EN v1.0 Address: 0x80056A88
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80058EB8
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056a88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short param_11,short param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  short *psVar2;
  short *psVar3;
  uint uVar4;
  short sVar5;
  short sVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  
  uVar7 = FUN_8028683c();
  psVar2 = DAT_803ddaf8;
  psVar3 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar1 = param_13 * 0x1c;
  FUN_80017640(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803ddaf8,0x1d
               ,*(int *)(DAT_803ddafc + iVar1),
               *(int *)(DAT_803ddafc + iVar1 + 8) - *(int *)(DAT_803ddafc + iVar1),param_13,param_14
               ,param_15,param_16);
  *(int *)(psVar2 + 6) =
       (int)psVar2 + (*(int *)(DAT_803ddafc + iVar1 + 4) - *(int *)(DAT_803ddafc + iVar1));
  *psVar3 = param_11 - psVar2[2];
  psVar3[2] = param_12 - psVar2[3];
  psVar3[1] = *psVar3 + *psVar2 + -1;
  psVar3[3] = psVar3[2] + psVar2[1] + -1;
  *(char *)(psVar3 + 4) = (char)psVar2[2];
  *(char *)((int)psVar3 + 9) = (char)psVar2[3];
  for (sVar6 = 0; sVar6 < psVar2[1]; sVar6 = sVar6 + 1) {
    for (sVar5 = 0; (int)sVar5 < (int)*psVar2; sVar5 = sVar5 + 1) {
      uVar4 = (int)sVar5 + (int)sVar6 * (int)*psVar2;
      if ((*(uint *)(*(int *)(psVar2 + 6) + uVar4 * 4) >> 0x17 & 0xff) != 0xff) {
        *(byte *)((int)uVar7 + ((int)uVar4 >> 3)) =
             *(byte *)((int)uVar7 + ((int)uVar4 >> 3)) | (byte)(1 << (uVar4 & 7));
      }
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80056c88
 * EN v1.0 Address: 0x80056C88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80059024
 * EN v1.1 Size: 1084b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056c88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056c8c
 * EN v1.0 Address: 0x80056C8C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80059460
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056c8c(void)
{
  int iVar1;
  int iVar2;
  
  iVar2 = (int)*(short *)(DAT_80382f00 + 0x594);
  if (*(short *)(DAT_80382f00 + 0x594) < 0) {
    iVar2 = DAT_803dc2a8;
  }
  if (iVar2 < 0) {
    return 0;
  }
  iVar1 = (&DAT_803870c8)[iVar2];
  if (iVar1 == 0) {
    return 0;
  }
  DAT_803dc2a8 = iVar2;
  DAT_803ddb20 = iVar1;
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80056cdc
 * EN v1.0 Address: 0x80056CDC
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x800594B0
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80056cdc(int param_1,int param_2)
{
  return DAT_80382f00 + (param_1 + param_2 * 0x10) * 0xc;
}

/*
 * --INFO--
 *
 * Function: FUN_80056cf4
 * EN v1.0 Address: 0x80056CF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800594D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056cf4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined2 *param_11,int param_12)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056cf8
 * EN v1.0 Address: 0x80056CF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800597C0
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056cf8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80056cfc
 * EN v1.0 Address: 0x80056CFC
 * EN v1.0 Size: 844b
 * EN v1.1 Address: 0x800598A8
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80056cfc(void)
{
  byte *pbVar1;
  short sVar2;
  bool bVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  int in_r6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  short *psVar10;
  int iVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286834();
  iVar11 = (int)((ulonglong)uVar12 >> 0x20);
  puVar6 = (uint *)uVar12;
  bVar3 = false;
  uVar7 = 0;
  psVar10 = *(short **)(iVar11 + 0x20);
  uVar9 = (uint)*(ushort *)(iVar11 + 8);
  if (uVar9 != 0) {
    iVar8 = 0;
    if (in_r6 == 0) {
      puVar6[0x21] = 0xffffffff;
      *puVar6 = 0xffffffff;
      puVar6[1] = 0xffffffff;
      puVar6[2] = 0xffffffff;
      puVar6[3] = 0xffffffff;
      puVar6[4] = 0xffffffff;
      puVar6[5] = 0xffffffff;
      puVar6[6] = 0xffffffff;
      puVar6[7] = 0xffffffff;
      puVar6[8] = 0xffffffff;
      puVar6[9] = 0xffffffff;
      puVar6[10] = 0xffffffff;
      puVar6[0xb] = 0xffffffff;
      puVar6[0xc] = 0xffffffff;
      puVar6[0xd] = 0xffffffff;
      puVar6[0xe] = 0xffffffff;
      puVar6[0xf] = 0xffffffff;
      puVar6[0x10] = 0xffffffff;
      puVar6[0x11] = 0xffffffff;
      puVar6[0x12] = 0xffffffff;
      puVar6[0x13] = 0xffffffff;
      puVar6[0x14] = 0xffffffff;
      puVar6[0x15] = 0xffffffff;
      puVar6[0x16] = 0xffffffff;
      puVar6[0x17] = 0xffffffff;
      puVar6[0x18] = 0xffffffff;
      puVar6[0x19] = 0xffffffff;
      puVar6[0x1a] = 0xffffffff;
      puVar6[0x1b] = 0xffffffff;
      puVar6[0x1c] = 0xffffffff;
      puVar6[0x1d] = 0xffffffff;
      puVar6[0x1e] = 0xffffffff;
      puVar6[0x1f] = 0xffffffff;
    }
    for (; iVar8 < (int)uVar9; iVar8 = iVar8 + (uint)*pbVar1 * 4) {
      if (in_r6 == 0) {
        sVar2 = *psVar10;
        if ((sVar2 == 0x6e) || (sVar2 == 5)) {
          if (sVar2 == 0x6e) {
            (**(code **)(*DAT_803dd71c + 8))(psVar10);
          }
          else {
            (**(code **)(*DAT_803dd6ec + 8))(psVar10);
          }
          if (!bVar3) {
            puVar6[0x21] = (int)psVar10 - *(int *)(iVar11 + 0x20);
            bVar3 = true;
          }
        }
        else if (((*(byte *)(psVar10 + 2) & 0x10) != 0) &&
                ((uVar7 & 1 << (uint)*(byte *)(psVar10 + 3)) == 0)) {
          puVar6[*(byte *)(psVar10 + 3)] = (int)psVar10 - *(int *)(iVar11 + 0x20);
          uVar7 = uVar7 | 1 << (uint)*(byte *)(psVar10 + 3);
        }
      }
      else {
        if (*psVar10 == 0x6e) {
          (**(code **)(*DAT_803dd71c + 0xc))(psVar10);
        }
        if (*psVar10 == 5) {
          (**(code **)(*DAT_803dd6ec + 0xc))(psVar10);
        }
      }
      pbVar1 = (byte *)(psVar10 + 1);
      psVar10 = psVar10 + (uint)*pbVar1 * 2;
    }
    if (in_r6 == 0) {
      uVar4 = puVar6[0x21];
      uVar7 = uVar9;
      if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar9)) {
        uVar7 = uVar4;
      }
      iVar11 = 4;
      puVar5 = puVar6;
      do {
        uVar4 = *puVar5;
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[1];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[2];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[3];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[4];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[5];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[6];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[7];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        puVar5 = puVar5 + 8;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      puVar6[0x22] = uVar7;
      if (puVar6[0x21] == 0xffffffff) {
        puVar6[0x20] = uVar9;
      }
      else {
        puVar6[0x20] = puVar6[0x21];
      }
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80057048
 * EN v1.0 Address: 0x80057048
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80059BCC
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057048(int param_1)
{
  if ((&DAT_803870c8)[param_1] != 0) {
    FUN_80056cfc();
    FUN_80017814((&DAT_803870c8)[param_1]);
    (&DAT_803870c8)[param_1] = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005709c
 * EN v1.0 Address: 0x8005709C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x80059C3C
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005709c(int param_1,int param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  char *pcVar3;
  short *psVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar6 = 0;
  iVar7 = 0x40;
  pcVar3 = DAT_80382ea4;
  psVar4 = DAT_80382e9c;
  iVar5 = DAT_80382ea8;
  while (((((int)DAT_803dda61 + (int)(char)(&DAT_803dc284)[param_3] != (int)*pcVar3 ||
           (iVar1 = (int)*psVar4, param_1 < iVar1)) || (psVar4[1] < param_1)) ||
         (((param_2 < psVar4[2] || (psVar4[3] < param_2)) ||
          (uVar2 = (param_1 - iVar1) + (param_2 - psVar4[2]) * ((psVar4[1] - iVar1) + 1),
          (1 << (uVar2 & 7) & (uint)*(byte *)(iVar5 + ((int)uVar2 >> 3))) == 0))))) {
    if ((((int)DAT_803dda61 + (int)(char)(&DAT_803dc284)[param_3] == (int)pcVar3[1]) &&
        (iVar1 = (int)psVar4[5], iVar1 <= param_1)) &&
       ((param_1 <= psVar4[6] &&
        (((psVar4[7] <= param_2 && (param_2 <= psVar4[8])) &&
         (uVar2 = (param_1 - iVar1) + (param_2 - psVar4[7]) * ((psVar4[6] - iVar1) + 1),
         (1 << (uVar2 & 7) & (uint)*(byte *)(iVar5 + 0x40 + ((int)uVar2 >> 3))) != 0)))))) {
      return iVar6 + 1;
    }
    psVar4 = psVar4 + 10;
    iVar5 = iVar5 + 0x80;
    pcVar3 = pcVar3 + 2;
    iVar6 = iVar6 + 2;
    iVar7 = iVar7 + -1;
    if (iVar7 == 0) {
      return -1;
    }
  }
  return iVar6;
}

/*
 * --INFO--
 *
 * Function: FUN_800571f8
 * EN v1.0 Address: 0x800571F8
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80059DA8
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800571f8(undefined *param_1)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar1 = (int)DAT_803dda6c;
    piVar3 = &DAT_80382eac;
    if (0 < iVar1) {
      do {
        if ((*piVar3 != 0) && (iVar4 == *(short *)(piVar3 + 1))) goto LAB_80059dfc;
        piVar3 = piVar3 + 2;
        iVar2 = iVar2 + 1;
        iVar1 = iVar1 + -1;
      } while (iVar1 != 0);
    }
    iVar2 = -1;
LAB_80059dfc:
    if (iVar2 == -1) {
      *param_1 = 0;
    }
    else {
      *param_1 = 1;
    }
    iVar4 = iVar4 + 1;
    param_1 = param_1 + 1;
    if (0x77 < iVar4) {
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80057270
 * EN v1.0 Address: 0x80057270
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80059E2C
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057270(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80057274
 * EN v1.0 Address: 0x80057274
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x8005A05C
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057274(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  int local_28;
  int iStack_24;
  int local_20 [8];
  
  uVar8 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar8 >> 0x20);
  iVar4 = iVar2 * 7;
  iVar3 = iVar2 * 0x1c;
  uVar6 = *(uint *)(DAT_803ddafc + iVar3);
  uVar5 = *(int *)(DAT_803ddafc + iVar3 + 0x1c) - uVar6;
  uVar7 = FUN_80044f74(uVar6,local_20,&iStack_24,&local_28,iVar4);
  DAT_803ddb20 = FUN_80017830(uVar5 + (local_20[0] + 7 >> 3) + 0x401 + local_28,5);
  uVar7 = FUN_80045328(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1d,
                       DAT_803ddb20,uVar6,uVar5,iVar4,in_r8,in_r9,in_r10);
  *(uint *)(DAT_803ddb20 + 0xc) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 4)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x14) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 8)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x30) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0xc)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x2c) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x10)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x34) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x14)) - uVar6;
  *(uint *)(DAT_803ddb20 + 0x20) = (DAT_803ddb20 + *(int *)(DAT_803ddafc + iVar3 + 0x18)) - uVar6;
  piRomLoadSection(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               *(undefined4 *)(DAT_803ddafc + iVar3 + 0x18),iVar2,*(uint *)(DAT_803ddb20 + 0x20),
               uVar5,iVar4,in_r8,in_r9,in_r10);
  *(uint *)(DAT_803ddb20 + 0x10) =
       (local_28 + *(int *)(DAT_803ddafc + iVar3 + 0x1c) + DAT_803ddb20) - uVar6;
  for (iVar3 = 0; fVar1 = lbl_803DF84C, iVar3 < (local_20[0] + 7 >> 3) + 1; iVar3 = iVar3 + 1) {
    *(undefined *)(*(int *)(DAT_803ddb20 + 0x10) + iVar3) = 0;
  }
  *(float *)(DAT_803ddb20 + 0x24) = lbl_803DF84C;
  *(float *)(DAT_803ddb20 + 0x28) = fVar1;
  *(undefined *)(DAT_803ddb20 + 0x18) = 0;
  *(undefined *)(DAT_803ddb20 + 0x19) = 0;
  if ((int)uVar8 == 0) {
    FUN_80056cfc();
    (**(code **)(*DAT_803dd72c + 0x58))(iVar2);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800575b4
 * EN v1.0 Address: 0x800575B4
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x8005A288
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800575b4(double param_1,float *param_2)
{
  uint uVar1;
  byte bVar2;
  
  bVar2 = 0;
  while( true ) {
    if (4 < bVar2) {
      return 1;
    }
    uVar1 = (uint)bVar2;
    if ((float)(param_1 +
               (double)((float)(&DAT_803885a8)[uVar1 * 5] +
                       (float)(&DAT_803885a4)[uVar1 * 5] * (param_2[2] - lbl_803DDA5C) +
                       param_2[1] * (float)(&DAT_803885a0)[uVar1 * 5] +
                       (float)(&DAT_8038859c)[uVar1 * 5] * (*param_2 - lbl_803DDA58))) <
        lbl_803DF84C) break;
    bVar2 = bVar2 + 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80057690
 * EN v1.0 Address: 0x80057690
 * EN v1.0 Size: 828b
 * EN v1.1 Address: 0x8005A310
 * EN v1.1 Size: 712b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80057690(int param_1)
{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  float fStack_48;
  float fStack_44;
  float local_40;
  float fStack_3c;
  undefined auStack_38 [4];
  undefined auStack_34 [4];
  undefined8 local_30;
  
  if (*(byte *)(param_1 + 0x36) == 0) {
    *(undefined *)(param_1 + 0x37) = 0;
    return 0;
  }
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 1) == 0)) {
    dVar9 = (double)*(float *)(param_1 + 0x40);
    if (dVar9 < (double)lbl_803DF838) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    iVar2 = FUN_80017a98();
    if (((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 2) == 0)) || (iVar2 == 0)) {
      dVar8 = (double)FUN_80006958((double)*(float *)(param_1 + 0x18),
                                   (double)*(float *)(param_1 + 0x1c),
                                   (double)*(float *)(param_1 + 0x20));
    }
    else {
      dVar8 = (double)FUN_8001771c((float *)(param_1 + 0x18),(float *)(iVar2 + 0x18));
    }
    if (dVar9 < dVar8) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    uVar6 = 0xff;
    dVar7 = (double)(float)(dVar9 - (double)lbl_803DF854);
    if (dVar7 < dVar8) {
      uVar6 = (uint)(lbl_803DF858 *
                    (lbl_803DF85C - (float)(dVar8 - dVar7) / (float)(dVar9 - dVar7)));
      local_30 = (double)(longlong)(int)uVar6;
    }
    FUN_8000693c((double)(*(float *)(param_1 + 0x18) - lbl_803DDA58),
                 (double)*(float *)(param_1 + 0x1c),
                 (double)(*(float *)(param_1 + 0x20) - lbl_803DDA5C),
                 (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),auStack_34,
                 auStack_38,&fStack_3c,&local_40,&fStack_44,&fStack_48);
    fVar1 = ABS(local_40) * lbl_803DF834;
    if (fVar1 < lbl_803DF860) {
      *(undefined *)(param_1 + 0x37) = 0;
      return 0;
    }
    if (fVar1 < lbl_803DF868) {
      local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      uVar6 = (uint)(((float)(local_30 - DOUBLE_803df840) * (fVar1 - lbl_803DF860)) /
                    lbl_803DF864);
    }
    *(char *)(param_1 + 0x37) = (char)(uVar6 * (*(byte *)(param_1 + 0x36) + 1) >> 8);
  }
  else {
    *(char *)(param_1 + 0x37) = (char)((*(byte *)(param_1 + 0x36) + 1) * 0xff >> 8);
  }
  if (*(char *)(param_1 + 0x37) == '\0') {
    uVar3 = 0;
  }
  else {
    for (bVar4 = 0; bVar4 < 5; bVar4 = bVar4 + 1) {
      uVar6 = (uint)bVar4;
      if (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8) +
          (float)(&DAT_803885a8)[uVar6 * 5] +
          (float)(&DAT_803885a4)[uVar6 * 5] * (*(float *)(param_1 + 0x20) - lbl_803DDA5C) +
          *(float *)(param_1 + 0x1c) * (float)(&DAT_803885a0)[uVar6 * 5] +
          (float)(&DAT_8038859c)[uVar6 * 5] * (*(float *)(param_1 + 0x18) - lbl_803DDA58) <
          lbl_803DF84C) {
        return 0;
      }
    }
    uVar3 = 1;
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_800579cc
 * EN v1.0 Address: 0x800579CC
 * EN v1.0 Size: 796b
 * EN v1.1 Address: 0x8005A5D8
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800579cc(undefined4 *param_1)
{
  float fVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 local_20;
  
  if (DAT_803dda6d != '\0') {
    dVar9 = (double)FUN_802924c4();
    iVar8 = (int)dVar9;
    dVar9 = (double)FUN_802924c4();
    iVar2 = (int)dVar9;
    if ((((iVar8 < 0) || (iVar2 < 0)) || (0xf < iVar8)) || (0xf < iVar2)) {
      iVar8 = 0;
    }
    else {
      iVar8 = (int)*(char *)(DAT_80382f14 + iVar8 + iVar2 * 0x10);
      if ((iVar8 < 0) || ((int)(uint)DAT_803ddb18 <= iVar8)) {
        iVar8 = 0;
      }
      else {
        iVar8 = *(int *)(DAT_803ddb1c + iVar8 * 4);
      }
    }
    dVar9 = (double)FUN_802924c4();
    dVar11 = (double)lbl_803DF834;
    dVar10 = (double)FUN_802924c4();
    iVar2 = (int)(*(float *)(DAT_803ddb28 + 0xc) -
                 (float)((double)CONCAT44(0x43300000,(int)(dVar11 * dVar9) ^ 0x80000000) -
                        DOUBLE_803df840));
    iVar3 = (int)(*(float *)(DAT_803ddb28 + 0x14) -
                 (float)((double)CONCAT44(0x43300000,
                                          (int)((double)lbl_803DF834 * dVar10) ^ 0x80000000) -
                        DOUBLE_803df840));
    if (iVar8 != 0) {
      uVar6 = (uint)*(short *)(iVar8 + 0x8a);
      uVar7 = uVar6;
      if ((uVar6 & 1) != 0) {
        uVar7 = uVar6 - 1;
      }
      fVar1 = *(float *)(DAT_803ddb28 + 0x10);
      uVar4 = (uint)*(short *)(iVar8 + 0x8c);
      local_20 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      if ((float)(local_20 - DOUBLE_803df840) < fVar1) {
        fVar1 = (float)((double)CONCAT44(0x43300000,uVar4 - 1 ^ 0x80000000) - DOUBLE_803df840);
      }
      uVar4 = uVar4 - uVar6;
      iVar8 = (int)uVar4 / 0x50 + ((int)uVar4 >> 0x1f);
      if (iVar8 - (iVar8 >> 0x1f) < 8) {
        iVar8 = ((int)uVar4 >> 3) + (uint)((int)uVar4 < 0 && (uVar4 & 7) != 0);
      }
      else {
        iVar8 = 0x50;
      }
      iVar2 = iVar2 / 0x50 + (iVar2 >> 0x1f);
      iVar3 = iVar3 / 0x50 + (iVar3 >> 0x1f);
      FUN_80135814();
      uVar6 = (uint)DAT_803ddaf0;
      iVar5 = (int)uVar6 >> 3;
      if ((uVar6 & 7) != 0) {
        iVar5 = iVar5 + 1;
      }
      FUN_80006adc(param_1,DAT_803ddaf4 +
                           iVar5 * (((int)((int)fVar1 - uVar7) / iVar8) * 0x40 +
                                    (iVar3 - (iVar3 >> 0x1f)) * 8 + (iVar2 - (iVar2 >> 0x1f))),uVar6
                   ,uVar6);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80057ce8
 * EN v1.0 Address: 0x80057CE8
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x8005A8A4
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80057ce8(uint param_1,uint param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float *pfVar9;
  uint uVar10;
  int iVar11;
  
  fVar1 = lbl_803DF834 *
          (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803df840);
  fVar2 = lbl_803DF834 *
          (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803df840);
  fVar3 = lbl_803DF86C;
  fVar4 = lbl_803DF870;
  if (param_3 != 0) {
    fVar3 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8a) ^ 0x80000000) -
                   DOUBLE_803df840);
    fVar4 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x8c) ^ 0x80000000) -
                   DOUBLE_803df840);
  }
  pfVar9 = (float *)&DAT_8038859c;
  iVar11 = 5;
  while( true ) {
    uVar10 = 0;
    bVar5 = false;
    while (((int)uVar10 < 8 && (!bVar5))) {
      fVar6 = lbl_803DF834 + fVar1;
      if ((uVar10 & 1) != 0) {
        fVar6 = fVar1;
      }
      fVar7 = lbl_803DF834 + fVar2;
      if ((uVar10 & 2) != 0) {
        fVar7 = fVar2;
      }
      fVar8 = fVar4;
      if ((uVar10 & 4) != 0) {
        fVar8 = fVar3;
      }
      if (lbl_803DF84C < fVar6 * *pfVar9 + fVar7 * pfVar9[2] + fVar8 * pfVar9[1] + pfVar9[3]) {
        bVar5 = true;
      }
      uVar10 = uVar10 + 1;
    }
    if ((uVar10 == 8) && (!bVar5)) break;
    pfVar9 = pfVar9 + 5;
    iVar11 = iVar11 + -1;
    if (iVar11 == 0) {
      return 1;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80057ea0
 * EN v1.0 Address: 0x80057EA0
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x8005AA20
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057ea0(float *param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_r8;
  
  for (iVar5 = 0; iVar5 < param_2; iVar5 = iVar5 + 1) {
    iVar3 = 0;
    fVar1 = lbl_803DF84C;
    while (iVar4 = iVar3, iVar4 < 0x18) {
      fVar2 = param_1[2] * (float)(&DAT_8030f194)[iVar4 + 2] +
              param_1[1] * (float)(&DAT_8030f194)[iVar4 + 1] +
              *param_1 * (float)(&DAT_8030f194)[iVar4];
      iVar3 = iVar4 + 3;
      if (fVar1 < fVar2) {
        in_r8 = iVar4;
        fVar1 = fVar2;
      }
    }
    switch(in_r8) {
    case 0:
      *(undefined *)(param_1 + 4) = 0;
      break;
    case 3:
      *(undefined *)(param_1 + 4) = 2;
      break;
    case 6:
      *(undefined *)(param_1 + 4) = 5;
      break;
    case 9:
      *(undefined *)(param_1 + 4) = 7;
      break;
    case 0xc:
      *(undefined *)(param_1 + 4) = 1;
      break;
    case 0xf:
      *(undefined *)(param_1 + 4) = 3;
      break;
    case 0x12:
      *(undefined *)(param_1 + 4) = 4;
      break;
    case 0x15:
      *(undefined *)(param_1 + 4) = 6;
    }
    param_1 = param_1 + 5;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80057fd0
 * EN v1.0 Address: 0x80057FD0
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x8005AB2C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80057fd0(void)
{
  int iVar1;
  undefined2 *puVar2;
  float *pfVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  double dVar7;
  float local_88;
  undefined4 local_84;
  float local_80;
  float afStack_7c [3];
  float local_70 [4];
  undefined4 local_60;
  float local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  FUN_80286840();
  local_5c = DAT_802c25d8;
  local_58 = DAT_802c25dc;
  local_54 = DAT_802c25e0;
  local_50 = DAT_802c25e4;
  local_4c = DAT_802c25e8;
  local_48 = DAT_802c25ec;
  local_44 = DAT_802c25f0;
  local_40 = DAT_802c25f4;
  local_3c = DAT_802c25f8;
  local_38 = DAT_802c25fc;
  local_34 = DAT_802c2600;
  local_30 = DAT_802c2604;
  local_2c = DAT_802c2608;
  local_28 = DAT_802c260c;
  local_24 = DAT_802c2610;
  local_70[0] = DAT_802c2614;
  local_70[1] = (float)DAT_802c2618;
  local_70[2] = (float)DAT_802c261c;
  local_70[3] = (float)DAT_802c2620;
  local_60 = DAT_802c2624;
  iVar1 = FUN_80017a98();
  puVar2 = FUN_800069a8();
  local_88 = *(float *)(puVar2 + 0x22) - lbl_803DDA58;
  local_84 = *(undefined4 *)(puVar2 + 0x24);
  local_80 = *(float *)(puVar2 + 0x26) - lbl_803DDA5C;
  pfVar3 = (float *)FUN_8000696c();
  if (iVar1 == 0) {
    dVar7 = (double)lbl_803DF874;
  }
  else {
    dVar7 = (double)FUN_80006958((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
    dVar7 = -dVar7;
  }
  local_70[0] = (float)dVar7;
  iVar1 = 0;
  pfVar6 = (float *)&DAT_80388538;
  pfVar5 = &local_5c;
  pfVar4 = local_70;
  do {
    FUN_80247bf8(pfVar3,pfVar5,pfVar6);
    FUN_80247edc((double)*pfVar4,pfVar6,afStack_7c);
    FUN_80247e94(&local_88,afStack_7c,afStack_7c);
    dVar7 = FUN_80247f90(afStack_7c,pfVar6);
    pfVar6[3] = (float)-dVar7;
    pfVar6 = pfVar6 + 5;
    pfVar5 = pfVar5 + 3;
    pfVar4 = pfVar4 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 5);
  FUN_80057ea0((float *)&DAT_80388538,5);
  FUN_8028688c();
  return;
}

/* 8b "li r3, N; blr" returners. */
int return0_80056694(void) { return 0x0; }
int return0_8005669C(void) { return 0x0; }

/* 12b 3-insn patterns. */
extern s8 curMapLayer;
extern s8 lbl_803DCEA4;
extern s16 lbl_803DCEB4;
extern s16 lbl_803DCEB6;
extern u32 renderFlags;
s32 getCurMapLayer(void) { return curMapLayer; }
s32 getCurMapType(void) { return lbl_803DCEA4; }

/* 20b reset triplet. */
void mapReloadWithFadeout(void) {
	lbl_803DCEA4 = 0;
	lbl_803DCEB6 = 0;
	lbl_803DCEB4 = 0;
}

/* 16b sda lookup. */
extern int lbl_803DCE6C;
void* mapTextureOverrideGetEntry(int idx) {
	return (void*)(lbl_803DCE6C + (idx << 4));
}

/* 32b two-stage table lookup via lis/addi/lwz. */
extern int lbl_803822A0[5];
#pragma scheduling off
void* fn_80059334(int a, int b) {
	int* base = (int*)lbl_803822A0[0];
	return (char*)base + (a + (b << 4)) * 12;
}
#pragma scheduling reset

/* 48b paired float reads scaled by sda21 constant. */
extern int lbl_803DCE68;
extern f32 lbl_803DEBC8;

#pragma scheduling off
void mapTextureScrollGetOffset(int idx, float* outX, float* outY) {
	f32 divisor;
	char* base;
	idx <<= 4;
	*outX = *(f32*)(lbl_803DCE68 + idx) / (divisor = lbl_803DEBC8);
	base = (char*)lbl_803DCE68 + idx;
	*outY = *(f32*)(base + 4) / divisor;
}
#pragma scheduling reset

/* 52b layer clamp pair. */
#pragma scheduling off
void goToPrevMapLayer(void) {
	curMapLayer = curMapLayer - 1;
	if (curMapLayer < -2) {
		curMapLayer = -2;
	}
	renderFlags |= 0x4000;
}

void goToNextMapLayer(void) {
	curMapLayer = curMapLayer + 1;
	if (curMapLayer > 2) {
		curMapLayer = 2;
	}
	renderFlags |= 0x4000;
}
#pragma scheduling reset

/* 132b per-block flag scan. */
typedef struct {
	u32 field_0;
	s16 field_4;
	u16 field_6;
} BlockEntry;

extern BlockEntry lbl_8038224C[8];
extern s8 lbl_803DCDEC;

#pragma scheduling off
void mapBlockFn_80059c2c(u8* outFlags) {
	int outer;
	for (outer = 0; outer < 0x78; outer++) {
		int i;
		int found = -1;
		s8 limit = lbl_803DCDEC;
		for (i = 0; i < limit; i++) {
			if (lbl_8038224C[i].field_0 != 0 && lbl_8038224C[i].field_4 == outer) {
				found = i;
				break;
			}
		}
		if (found == -1) {
			outFlags[outer] = 0;
		} else {
			outFlags[outer] = 1;
		}
	}
}
#pragma scheduling reset

/* 136b 5-plane view-frustum sphere visibility test. */
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DEBCC;
extern char gViewFrustumPlanes[];

#pragma scheduling off
int ViewFrustum_IsSphereVisible(float* center, float radius) {
	u8 i;
	for (i = 0; i < 5; i++) {
		float* plane = (float*)(gViewFrustumPlanes + i * 0x14);
		float dot = plane[0] * (center[0] - playerMapOffsetX)
		          + center[1] * plane[1]
		          + plane[2] * (center[2] - playerMapOffsetZ)
		          + plane[3];
		if (radius + dot < lbl_803DEBCC) return 0;
	}
	return 1;
}
#pragma scheduling reset

/* 112b indexed teardown/free of map block. */
extern char lbl_803822C8[];
extern void* gLoadedRomListPages[];
extern void defStartFn_8005972c(char* p1, u32* p2, int idx, int flag);
extern void mm_free(void* p);

#pragma scheduling off
#pragma peephole off
void fn_80059A50(int param_1) {
	int idx = param_1;
	void* p = gLoadedRomListPages[idx];
	if (p != 0) {
		defStartFn_8005972c(p, (u32*)(lbl_803822C8 + idx * 0x8C), idx, 1);
		mm_free(gLoadedRomListPages[idx]);
		gLoadedRomListPages[idx] = 0;
	}
}
#pragma peephole reset
#pragma scheduling reset

/* 96b camera-pos gated load. */
extern f32 lbl_803DCE5C;
extern f32 lbl_803DCE60;
extern f32 lbl_803DCE64;
extern void doPendingMapLoads(void);

#pragma peephole off
#pragma scheduling off
void loadMapForCameraPos(float x, float y, float z) {
	if ((renderFlags & 2) != 0 && (renderFlags & 0x800) == 0) return;
	lbl_803DCE64 = x;
	lbl_803DCE60 = y;
	lbl_803DCE5C = z;
	renderFlags |= 2;
	if ((renderFlags & 0x800) != 0) {
		doPendingMapLoads();
	}
}
#pragma peephole reset
#pragma scheduling reset

/* 80b current map block lookup. */
extern int lbl_803DB648;
extern void* lbl_803DCEA0;
extern void* gLoadedRomListPages[];

#pragma scheduling off
void* mapBlockFn_800592e4(void) {
	char* p = (char*)lbl_803822A0[0];
	int v = *(s16*)(p + 0x594);
	if (v < 0) {
		v = lbl_803DB648;
	}
	if (v < 0) {
		return 0;
	}
	{
		void* res = gLoadedRomListPages[v];
		if (res == 0) {
			return res;
		}
		lbl_803DB648 = v;
		lbl_803DCEA0 = res;
		return res;
	}
}
#pragma scheduling reset

/* 104b conditional gameTextLoadDir caller. */
extern int lbl_803DCEC4;
extern int lbl_803DCEC8;
extern s8 lbl_8030E55C[];
extern void gameTextLoadDir(int dirId);

#pragma peephole off
#pragma scheduling off
void gameTextLoadForMap_800571f0(u8 force) {
	int curVal = lbl_803DCEC8;
	if (curVal == -1) return;
	if (curVal == lbl_803DCEC4 && force == 0) return;
	lbl_803DCEC4 = curVal;
	if (curVal >= 0x76) return;
	{
		s8 entry = lbl_8030E55C[curVal];
		if (entry == -1) return;
		gameTextLoadDir(entry);
	}
}
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
void mapTextureScrollSetStep(int idx, int xStep, int yStep, int texWidthFixed, int texHeightFixed) {
    int base = lbl_803DCE68 + idx * 16;
    *(s16*)(base + 8) = (s16)((xStep << 16) / (texWidthFixed >> 6));
    *(s16*)(base + 10) = (s16)((yStep << 16) / (texHeightFixed >> 6));
}
#pragma peephole reset
#pragma scheduling reset

extern f32 gMapBlockWorldSize;
extern s8 lbl_803DB624;
extern int lbl_803DCE78;
extern int* gMapEventInterface;
extern f32 fastFloorf(f32 v);
extern int mapCoordsToId(int x, int z, int layer);
extern int getDataFileSize(int kind);
extern void getTabEntry(int base, int kind, int offset, int size);

#pragma scheduling off
#pragma peephole off
void mapSetup(int mapType, s32* outMapId, s32* outEvent, f32 a, f32 b, f32 c)
{
    int layer;
    int tabEntry;
    int mapId;
    int mapY;
    s8* arr;

    layer = 0;
    arr = &lbl_803DB624;
    if (arr[0] != mapType) {
        layer = 1;
        if (arr[1] != mapType) {
            layer = 2;
            if (arr[2] != mapType) {
                layer = 3;
                if (arr[3] != mapType) {
                    layer = 4;
                    if (arr[4] != mapType) {
                        layer = 5;
                    }
                }
            }
        }
    }
    curMapLayer = 0;
    mapY = (s32)fastFloorf(c / gMapBlockWorldSize);
    mapId = mapCoordsToId((s32)fastFloorf(a / gMapBlockWorldSize), mapY, layer);
    if (mapId < 0 || mapId >= (getDataFileSize(0x1f) >> 5)) {
        lbl_803DCEA4 = 0;
    } else {
        tabEntry = lbl_803DCE78;
        getTabEntry(tabEntry, 0x1f, mapId << 5, 0x20);
        lbl_803DCEA4 = *(s8*)(tabEntry + 0x1c);
    }
    lbl_803DCEB4 = 0;
    if (lbl_803DCEA4 == 1) {
        lbl_803DCEB6 = (s16)mapId;
        lbl_803DCEB4 = *(s16*)(tabEntry + 0x1e);
    }
    *outMapId = mapId;
    if (mapId != -1) {
        *outEvent = (s32)*(s8*)((*(int(**)(void))(*gMapEventInterface + 0x90))() + 0xe);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int gMapBlockLayerTables[5];
extern s16* lbl_803DCE94;
extern u8 lbl_803DCE98;
extern u8* lbl_803DCE8C;
extern void mapBlockFn_80059354(int p1, int p2, s16* entry, int layer);
extern int mapCheckCurBlocks(int v);
extern void* MapBlock_loadFromFile(int blockId);
extern void MapBlock_init(void* blk);
extern int textureLoad(int id, int param);
extern void MapBlock_initHits(void* blk, int blockId);
extern void MapBlock_initShaders(void* blk);
extern void trackLoadBlockEnd(void* blk, int blockId, int slotIdx, int layer);
extern int return0_80060B90(void* blk);
extern void DCStoreRange(void* p, int size);

#pragma scheduling off
#pragma peephole off
int mapLoadBlock(int p1, int p2, int p3, int p4, int layer)
{
    int blockId;
    char* entry;
    s8* statusArr;
    int slotIdx;
    s16* arr;
    int i;
    void* blk;
    int byteOff;

    entry = (char*)lbl_803822A0[layer];
    statusArr = (s8*)gMapBlockLayerTables[layer];
    slotIdx = p1 + (p2 << 4);
    entry += slotIdx * 12;

    mapBlockFn_80059354(p3, p4, (s16*)entry, layer);

    blockId = *(s16*)(entry + 6);
    if (mapCheckCurBlocks(*(s8*)(entry + 9)) == -1) {
        statusArr[slotIdx] = -1;
        return 0;
    }
    if (blockId < 0) {
        blockId = -1;
    }
    if (blockId < 0) {
        statusArr[slotIdx] = (s8)blockId;
        return 0;
    }
    statusArr[slotIdx] = -1;

    arr = lbl_803DCE94;
    for (i = 0; i < lbl_803DCE98; i++) {
        if (*arr == blockId) {
            lbl_803DCE8C[i]++;
            statusArr[slotIdx] = (s8)i;
            return 1;
        }
        arr++;
    }

    blk = MapBlock_loadFromFile(blockId);
    if (blk == NULL) {
        return 1;
    }
    MapBlock_init(blk);
    i = 0;
    byteOff = 0;
    while (i < *(u8*)((char*)blk + 0xa0)) {
        int v = *(int*)(*(int*)((char*)blk + 0x54) + byteOff);
        v = -(int)((u32)v | 0x8000);
        *(int*)(*(int*)((char*)blk + 0x54) + byteOff) = textureLoad(v, 0);
        byteOff += 4;
        i++;
    }
    MapBlock_initHits(blk, blockId);
    MapBlock_initShaders(blk);
    trackLoadBlockEnd(blk, blockId, slotIdx, layer);
    *(int*)blk = return0_80060B90(blk);
    DCStoreRange(blk, *(int*)((char*)blk + 0x8));
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct { f32 v[15]; } _PlanePack;
typedef struct { f32 v[5]; } _ScalePack;
typedef struct { f32 x, y, z; } _Vec3;

extern _PlanePack lbl_802C1E58;
extern _ScalePack lbl_802C1E94;
extern f32 lbl_803878D8[];
extern f32 PostCB_803DEBF4;
extern int* Obj_GetPlayerObject(void);
extern int* Camera_GetCurrentViewSlot(void);
extern f32* Camera_GetInverseViewRotationMatrix(void);
extern f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z);
extern void PSMTXMultVec(f32* mtx, _Vec3* in, f32* out);
extern void PSVECScale(f32* in, _Vec3* out, f32 s);
extern void PSVECAdd(_Vec3* a, _Vec3* b, _Vec3* out);
extern f32 PSVECDotProduct(_Vec3* a, f32* b);
extern void fn_8005A8A4(f32* planes, int count);

#pragma scheduling off
#pragma peephole off
void playerVecFn_8005a9b0(void)
{
    _Vec3 camPos;
    _Vec3 tmp;
    _ScalePack scales;
    _PlanePack planes;
    int* player;
    int* viewSlot;
    f32* invRotMtx;
    int i;
    f32* outPtr;
    f32* dirPtr;
    f32* scalePtr;
    f32 clipDist;

    planes = lbl_802C1E58;
    scales = lbl_802C1E94;
    player = Obj_GetPlayerObject();
    viewSlot = Camera_GetCurrentViewSlot();
    camPos.x = *(f32*)((char*)viewSlot + 0x44) - playerMapOffsetX;
    camPos.y = *(f32*)((char*)viewSlot + 0x48);
    camPos.z = *(f32*)((char*)viewSlot + 0x4c) - playerMapOffsetZ;
    invRotMtx = Camera_GetInverseViewRotationMatrix();
    if (player != NULL) {
        clipDist = -Camera_DistanceToCurrentViewPosition(
            *(f32*)((char*)player + 0x18),
            *(f32*)((char*)player + 0x1c),
            *(f32*)((char*)player + 0x20));
    } else {
        clipDist = PostCB_803DEBF4;
    }
    scales.v[0] = clipDist;

    i = 0;
    outPtr = lbl_803878D8;
    dirPtr = planes.v;
    scalePtr = scales.v;
    for (; i < 5; i++) {
        PSMTXMultVec(invRotMtx, (_Vec3*)dirPtr, outPtr);
        PSVECScale(outPtr, &tmp, *scalePtr);
        PSVECAdd(&camPos, &tmp, &tmp);
        outPtr[3] = -PSVECDotProduct(&tmp, outPtr);
        outPtr += 5;
        dirPtr += 3;
        scalePtr++;
    }
    fn_8005A8A4(lbl_803878D8, 5);
}
#pragma peephole reset
#pragma scheduling reset

extern int* lbl_803DCE9C;
extern void setMapBlockFlag(void);
extern void OSReport(const char* fmt, ...);
extern char sTrackLoadBlockOverrunError[];

#pragma scheduling off
#pragma peephole off
void trackLoadBlockEnd(void* blk, int blockId, int slotIdx, int layer)
{
    int i;
    s16* arr;
    int count;
    s8* statusArr;

    i = 0;
    arr = lbl_803DCE94;
    count = lbl_803DCE98;
    for (; i < count; i++) {
        if (*arr == -1) break;
        arr++;
    }
    if (i == count) {
        lbl_803DCE98 = (u8)(lbl_803DCE98 + 1);
        if (lbl_803DCE98 == 0x40) {
            OSReport(sTrackLoadBlockOverrunError);
        }
    }
    statusArr = (s8*)gMapBlockLayerTables[layer];
    statusArr[slotIdx] = (s8)i;
    lbl_803DCE9C[i] = (int)blk;
    lbl_803DCE94[i] = (s16)blockId;
    lbl_803DCE8C[i] = 1;
    setMapBlockFlag();
}
#pragma peephole reset
#pragma scheduling reset

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void mapTextureOverrideRelease(int key, int type)
{
    int i;
    int off;

    for (i = 0; i < 80; i++) {
        off = i * 0x10;
        if (key == *(u32 *)(lbl_803DCE6C + off) &&
            *(u8 *)(lbl_803DCE6C + off + 0xe) == type &&
            *(s16 *)(lbl_803DCE6C + off + 0xc) > 0) {
            *(s16 *)(lbl_803DCE6C + off + 0xc) -= 1;
            if (*(s16 *)(lbl_803DCE6C + off + 0xc) == 0) {
                *(int *)(lbl_803DCE6C + off + 4) = 0;
                *(u8 *)(lbl_803DCE6C + off + 0xe) = 0;
                *(int *)(lbl_803DCE6C + off) = 0;
                *(int *)(lbl_803DCE6C + off + 8) = 0;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void mapTextureOverrideSetValue(int type, u32 key, int value)
{
    int i;
    int off;

    for (i = 0; i < 80; i++) {
        off = i * 0x10;
        if (*(s16 *)(lbl_803DCE6C + off + 0xc) > 0 &&
            *(u32 *)(lbl_803DCE6C + off) == key &&
            type == *(u8 *)(lbl_803DCE6C + off + 0xe)) {
            *(int *)(lbl_803DCE6C + off + 4) = value;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int mapGetRomListAndOffsets(int p1, int b);

#pragma scheduling off
#pragma peephole off
void mapLoadForObject(int p1, char *p2)
{
    int saved = lbl_803DCEC8;
    int romList = mapGetRomListAndOffsets(p1, 1);
    int slot = 0x50;
    int i;

    for (i = 0; i < 40; i++) {
        if (gLoadedRomListPages[slot] == NULL) {
            gLoadedRomListPages[slot] = (void *)romList;
            break;
        }
        slot++;
    }
    *(u8 *)(p2 + 0x34) = (u8)slot;
    (*(void (*)(int, int))(*(int *)(*gMapEventInterface + 0x48)))(p1, slot);
    defStartFn_8005972c((char *)romList, (u32*)&lbl_803822C8[slot * 0x8c], slot, 0);
    (*(void (*)(int))(*(int *)(*gMapEventInterface + 0x58)))(slot);
    lbl_803DCEC8 = saved;
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
int mapTextureScrollAcquire(int xStep, int yStep, int texWidthFixed, int texHeightFixed)
{
    char *base = (char *)lbl_803DCE68;
    char *e;
    int idx;
    int slot;

    e = base;
    for (idx = 0; idx < 0x3a; idx++) {
        if (*(s16 *)(e + 8) == xStep && *(s16 *)(e + 0xa) == yStep) {
            *(u8 *)(e + 0xc) += 1;
            return idx;
        }
        e += 0x10;
    }
    slot = -1;
    e = base;
    for (idx = 0; idx < 0x3a; idx++) {
        if (*(u8 *)(e + 0xc) == 0) {
            slot = idx;
            break;
        }
        e += 0x10;
    }
    if (slot == -1)
        return -1;
    e = base + slot * 0x10;
    *(s16 *)(e + 8) = (s16)((xStep << 16) / (texWidthFixed >> 6));
    *(s16 *)(e + 0xa) = (s16)((yStep << 16) / (texHeightFixed >> 6));
    *(f32 *)e = lbl_803DEBCC;
    *(f32 *)(e + 4) = lbl_803DEBCC;
    *(u8 *)(e + 0xc) += 1;
    return slot;
}
#pragma scheduling reset
#pragma peephole reset

extern int isRomListLoading(void);
extern void padUpdate(void);
extern void checkReset(void);
extern void waitNextFrame(void);
extern void loadDataFiles(void);
extern void dvdCheckError(void);
extern void mmFreeTick(int a);
extern void gameTextRun(void);
extern void GXFlush_(int, int);
extern int saveGame_restoreObjectPosToRomList(void* object);
extern char lbl_8037E0C0[];
extern u8 lbl_803DC950;
extern int lbl_803DB620;

#pragma scheduling off
#pragma peephole off
int mapProcessRomList(int slot)
{
    u8 flag;
    int i;
    int count;
    char* p;
    char* entry;
    s16* rects;
    char* cur;
    int j;
    int step;
    int rl;
    f32 dz, dx;
    char* base;

    base = lbl_8037E0C0;
    flag = 0;
    while (isRomListLoading()) {
        padUpdate();
        checkReset();
        if (flag)
            waitNextFrame();
        loadDataFiles();
        dvdCheckError();
        if (flag) {
            mmFreeTick(0);
            gameTextRun();
            GXFlush_(1, 0);
        }
        if (lbl_803DC950)
            flag = 1;
    }
    i = 0;
    p = base + 0x418C;
    count = lbl_803DCDEC;
    while (i < count && *(void**)p != 0) {
        p += 8;
        i++;
    }
    if (i == count)
        lbl_803DCDEC = lbl_803DCDEC + 1;
    rl = mapGetRomListAndOffsets(slot, 0);
    entry = base + i * 8 + 0x418C;
    *(int*)entry = rl;
    *(int*)(base + slot * 4 + 0x83A8) = rl;
    *(s16*)(base + i * 8 + 0x4190) = slot;
    lbl_803DCEA0 = *(void**)entry;
    rects = (s16*)(*(int*)(base + 0x417C) + slot * 10);
    *(u8*)((char*)lbl_803DCEA0 + 0x19) = *(u8*)(*(int*)(base + 0x4184) + slot);
    *(f32*)((char*)lbl_803DCEA0 + 0x24) =
        gMapBlockWorldSize * (f32)(rects[0] + *(s16*)((char*)lbl_803DCEA0 + 4));
    *(f32*)((char*)lbl_803DCEA0 + 0x28) =
        gMapBlockWorldSize * (f32)(rects[2] + *(s16*)((char*)lbl_803DCEA0 + 6));
    cur = (char*)lbl_803DCEA0;
    dz = *(f32*)(cur + 0x28);
    dx = *(f32*)(cur + 0x24);
    if (cur != 0) {
        char* obj = *(char**)(cur + 0x20);
        for (j = 0; j < *(u16*)(cur + 8); ) {
            if (saveGame_restoreObjectPosToRomList(obj) == 0) {
                *(f32*)(obj + 8) += dx;
                *(f32*)(obj + 0x10) += dz;
            }
            step = *(u8*)(obj + 2) * 4;
            j += step;
            obj += step;
        }
    }
    lbl_803DB620 = slot;
    return i;
}
#pragma peephole reset
#pragma scheduling reset

extern void *mmAlloc(int size, int heap, int flags);
extern void mapsBinGetRomlistSize(int offset, int *a, int *b, int *c);
extern void fileLoadToBufferOffset(int id, void *buf, int offset, int len);
extern int lbl_803DCE7C;

#pragma scheduling off
#pragma peephole off
int mapGetRomListAndOffsets(int p1, int flag)
{
    int tabOff = p1 * 7 << 2;
    int offset0 = *(int *)(lbl_803DCE7C + tabOff);
    int tailLen = *(int *)(lbl_803DCE7C + tabOff + 0x1c) - offset0;
    int v0, v1, v2;
    int i;

    mapsBinGetRomlistSize(offset0, &v0, &v1, &v2);
    lbl_803DCEA0 = mmAlloc(tailLen + ((v0 + 7 >> 3) + 0x401 + v2), 5, 0);
    fileLoadToBufferOffset(0x1d, lbl_803DCEA0, offset0, tailLen);

    *(int *)((char *)lbl_803DCEA0 + 0xc) = (int)lbl_803DCEA0 + *(int *)(lbl_803DCE7C + tabOff + 4) - offset0;
    *(int *)((char *)lbl_803DCEA0 + 0x14) = (int)lbl_803DCEA0 + *(int *)(lbl_803DCE7C + tabOff + 8) - offset0;
    *(int *)((char *)lbl_803DCEA0 + 0x30) = (int)lbl_803DCEA0 + *(int *)(lbl_803DCE7C + tabOff + 0xc) - offset0;
    *(int *)((char *)lbl_803DCEA0 + 0x2c) = (int)lbl_803DCEA0 + *(int *)(lbl_803DCE7C + tabOff + 0x10) - offset0;
    *(int *)((char *)lbl_803DCEA0 + 0x34) = (int)lbl_803DCEA0 + *(int *)(lbl_803DCE7C + tabOff + 0x14) - offset0;
    *(int *)((char *)lbl_803DCEA0 + 0x20) = (int)lbl_803DCEA0 + *(int *)(lbl_803DCE7C + tabOff + 0x18) - offset0;

    piRomLoadSection(*(int *)(lbl_803DCE7C + tabOff + 0x18), p1, *(int *)((char *)lbl_803DCEA0 + 0x20));
    *(int *)((char *)lbl_803DCEA0 + 0x10) = v2 + (*(int *)(lbl_803DCE7C + tabOff + 0x1c) + (int)lbl_803DCEA0) - offset0;

    for (i = 0; i < (v0 + 7 >> 3) + 1; i++) {
        *(u8 *)(*(int *)((char *)lbl_803DCEA0 + 0x10) + i) = 0;
    }
    *(f32 *)((char *)lbl_803DCEA0 + 0x24) = lbl_803DEBCC;
    *(f32 *)((char *)lbl_803DCEA0 + 0x28) = lbl_803DEBCC;
    *(u8 *)((char *)lbl_803DCEA0 + 0x18) = 0;
    *(u8 *)((char *)lbl_803DCEA0 + 0x19) = 0;
    if (flag == 0) {
        defStartFn_8005972c(lbl_803DCEA0, (u32*)&lbl_803822C8[p1 * 0x8c], p1, 0);
        (*(void (*)(int))(*(int *)(*gMapEventInterface + 0x58)))(p1);
    }
    return (int)lbl_803DCEA0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void mapInitSetRects(s16 *rect, u8 *bitmap, int p3, int p4, int idx)
{
    int self = lbl_803DCE78;
    int tabOff = idx * 7 << 2;
    int x, y;

    getTabEntry(self, 0x1d, *(int *)(lbl_803DCE7C + tabOff),
                *(int *)(lbl_803DCE7C + tabOff + 8) - *(int *)(lbl_803DCE7C + tabOff));
    *(int *)(self + 0xc) = self + *(int *)(lbl_803DCE7C + tabOff + 4) - *(int *)(lbl_803DCE7C + tabOff);
    rect[0] = p3 - *(s16 *)(self + 4);
    rect[2] = p4 - *(s16 *)(self + 6);
    rect[1] = rect[0] + *(s16 *)(self + 0) - 1;
    rect[3] = rect[2] + *(s16 *)(self + 2) - 1;
    *(u8 *)((char *)rect + 8) = *(s16 *)(self + 4);
    *(u8 *)((char *)rect + 9) = *(s16 *)(self + 6);
    for (y = 0; (s16)y < *(s16 *)(self + 2); y++) {
        for (x = 0; (s16)x < *(s16 *)(self + 0); x++) {
            int p = (s16)x + (s16)y * *(s16 *)(self + 0);
            if ((*(u32 *)(*(int *)(self + 0xc) + p * 4) >> 23 & 0xff) != 0xff) {
                bitmap[p >> 3] |= 1 << (p & 7);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
#pragma dont_inline reset

extern void Obj_UpdateWorldTransform(void);
extern void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern u8 lbl_80386648[];

#pragma scheduling off
#pragma peephole off
void playerUpdateFn_8005649c(void)
{
    int count;
    int **objs;
    char *cam;
    int **e;
    int i, slot;
    f32 lx, ly, lz;

    objs = ObjGroup_GetObjects(6, &count);
    cam = (char *)Camera_GetCurrentViewSlot();
    Obj_UpdateWorldTransform();
    for (i = 0; i < 31; i++)
        *(int *)(lbl_80386648 + i * 0x10 + 0xc) = 0;
    *(f32 *)(lbl_80386648 + 0) = *(f32 *)(cam + 0x44);
    *(f32 *)(lbl_80386648 + 4) = *(f32 *)(cam + 0x48);
    *(f32 *)(lbl_80386648 + 8) = *(f32 *)(cam + 0x4c);
    *(int *)(lbl_80386648 + 0xc) = 1;
    e = objs;
    for (i = 0; i < count; i++) {
        int *obj = *e;
        slot = *(s8 *)((char *)obj + 0x35) + 1;
        if (*(void **)(cam + 0x40) == (void *)obj) {
            *(f32 *)(lbl_80386648 + slot * 0x10 + 0) = *(f32 *)(cam + 0xc);
            *(f32 *)(lbl_80386648 + slot * 0x10 + 4) = *(f32 *)(cam + 0x10);
            *(f32 *)(lbl_80386648 + slot * 0x10 + 8) = *(f32 *)(cam + 0x14);
        } else {
            Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0x44), *(f32 *)(cam + 0x48), *(f32 *)(cam + 0x4c), &lx, &ly, &lz);
            *(f32 *)(lbl_80386648 + slot * 0x10 + 0) = lx;
            *(f32 *)(lbl_80386648 + slot * 0x10 + 4) = ly;
            *(f32 *)(lbl_80386648 + slot * 0x10 + 8) = lz;
        }
        *(int *)(lbl_80386648 + slot * 0x10 + 0xc) = 1;
        e++;
    }
}
#pragma scheduling reset
#pragma peephole reset

extern char sTrackGlobalTexanimOverflowError[];

#pragma scheduling off
#pragma peephole off
typedef struct TexOverrideEntry {
    u32 key;
    int data0;
    int data1;
    s16 refs;
    u8 type;
    u8 pad;
} TexOverrideEntry;

int mapTextureOverrideAcquire(int key, int value, int type)
{
    TexOverrideEntry *e;
    int idx;
    int found;
    TexOverrideEntry *e2;
    int idx2;

    found = -1;
    idx = 0;
    e = (TexOverrideEntry *)lbl_803DCE6C;
    for (; idx < 80; idx++) {
        if (e->refs != 0 && e->key == key && type == e->type) {
            found = idx;
            break;
        }
        e++;
    }
    if (found != -1) {
        ((TexOverrideEntry *)lbl_803DCE6C)[found].refs += 1;
        return found;
    }
    found = -1;
    idx2 = 0;
    e2 = (TexOverrideEntry *)lbl_803DCE6C;
    for (; idx2 < 80; idx2++) {
        if (e2->refs == 0) {
            found = idx2;
            break;
        }
        e2++;
    }
    if (found != -1) {
        ((TexOverrideEntry *)lbl_803DCE6C)[found].refs = 1;
        ((TexOverrideEntry *)lbl_803DCE6C)[found].data0 = 0;
        ((TexOverrideEntry *)lbl_803DCE6C)[found].data1 = value;
        ((TexOverrideEntry *)lbl_803DCE6C)[found].key = key;
        ((TexOverrideEntry *)lbl_803DCE6C)[found].type = type;
        return found;
    }
    OSReport(sTrackGlobalTexanimOverflowError);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

extern int* gCheckpointInterface;
extern int* gRomCurveInterface;
extern int* gNewCloudsInterface;
extern int* gCloudActionInterface;
extern void audioStopByMask(int mask);
extern void Sfx_ClearLoopedObjectSounds(void);
extern void doNothing_8001F678(int a, int b);
extern void Obj_ResetObjectSystem(void);
extern void textureFree(int id);
extern void voxmaps_resetLoadedMaps(void);
extern void textureFreeFn_8012fcec(void);
extern void fn_80133934(void);

#pragma scheduling off
#pragma peephole off
void unloadMap(void)
{
    int layer;
    int i;
    s8* cur;
    int mapType;
    int blk;
    int j;
    int k;
    int rb;
    char* p;
    int n;

    audioStopByMask(4);
    Sfx_ClearLoopedObjectSounds();
    doNothing_8001F678(1, 0);
    for (layer = 0; layer < 5; layer++) {
        cur = (s8*)gMapBlockLayerTables[layer];
        for (i = 0; i < 256; i++) {
            mapType = cur[i];
            if (mapType >= 0) {
                lbl_803DCE8C[mapType]--;
                if (lbl_803DCE8C[mapType] == 0) {
                    blk = lbl_803DCE9C[mapType];
                    lbl_803DCE94[mapType] = -1;
                    lbl_803DCE9C[mapType] = 0;
                    for (j = 0; j < *(u8*)(blk + 0xa2); j++) {
                        rb = *(int*)(blk + 0x64) + j * 68;
                        p = (char*)rb;
                        for (k = 0; k < *(u8*)(rb + 0x41); k++) {
                            u32 cell = *(u8*)(p + 0x2a);
                            if (cell != 0xff) {
                                if (*(u8*)(lbl_803DCE68 + cell * 16 + 12) != 0)
                                    *(u8*)(lbl_803DCE68 + cell * 16 + 12) -= 1;
                            }
                            if (*(u8*)(p + 0x29) != 0)
                                mapTextureOverrideRelease(*(int*)(p + 0x24), *(u8*)(p + 0x29));
                            p += 8;
                        }
                    }
                    for (j = 0; j < *(u8*)(blk + 0xa0); j++)
                        textureFree(*(int*)(*(int*)(blk + 0x54) + j * 4));
                    if (*(void**)(blk + 0x74) != 0)
                        mm_free(*(void**)(blk + 0x74));
                    if (*(void**)(blk + 0x70) != 0)
                        mm_free(*(void**)(blk + 0x70));
                    setMapBlockFlag();
                    mm_free((void*)blk);
                }
            }
        }
    }
    lbl_803DCE98 = 0;
    Obj_ResetObjectSystem();
    for (n = 0; n < 120; n++) {
        if (gLoadedRomListPages[n] != 0) {
            mm_free(gLoadedRomListPages[n]);
            gLoadedRomListPages[n] = 0;
        }
    }
    (*(void (*)(void))(*(int *)(*gCheckpointInterface + 4)))();
    (*(void (*)(void))(*(int *)(*gRomCurveInterface + 4)))();
    lbl_803DCDEC = 0;
    playerMapOffsetX = lbl_803DEBCC;
    playerMapOffsetZ = lbl_803DEBCC;
    voxmaps_resetLoadedMaps();
    textureFreeFn_8012fcec();
    fn_80133934();
    (*(void (*)(int, int))(*(int *)(*gNewCloudsInterface + 0xc)))(-1, 0);
    (*(void (*)(void))(*(int *)(*gCloudActionInterface + 0x14)))();
}
#pragma peephole reset
#pragma scheduling reset

extern int lbl_80382238[];
extern void loadAssetFileById(void* out, int id);
extern void* memset(void* p, int v, int n);

#pragma scheduling off
#pragma peephole off
void initMaps(void)
{
    void* data;
    int total;
    int i;
    int i2;
    int ofs;
    int idx;
    int o;
    int k;
    char* e;

    data = 0;
    total = getDataFileSize(0x15);
    loadAssetFileById(&data, 0x15);
    lbl_80382238[0] = -1;
    lbl_80382238[1] = (int)mmAlloc(1280, 5, 0);
    lbl_80382238[2] = (int)mmAlloc(512, 5, 0);
    lbl_80382238[3] = (int)mmAlloc(128, 5, 0);
    lbl_80382238[4] = (int)mmAlloc(8192, 5, 0);
    memset((void*)lbl_80382238[4], 0, 8192);
    idx = 0;
    ofs = 0;
    for (i = 0; i < 16; i++) {
        e = (char*)lbl_80382238[1] + ofs;
        *(s8*)((char*)lbl_80382238[3] + idx) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[idx << 1] = -1;
        ((s16*)lbl_80382238[2])[(idx << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 10);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 1)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 20);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 2)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 30);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 3)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 40);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 4)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 50);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 5)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 60);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 6)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        e = (char*)lbl_80382238[1] + (o = ofs + 70);
        *(s8*)((char*)lbl_80382238[3] + (k = idx + 7)) = -128;
        *(s16*)(e + 0) = -32768;
        *(s16*)(e + 2) = -32768;
        *(s16*)(e + 4) = -32768;
        *(s16*)(e + 6) = -32768;
        *(s8*)(e + 8) = -128;
        *(s8*)(e + 9) = -128;
        ((s16*)lbl_80382238[2])[k << 1] = -1;
        ((s16*)lbl_80382238[2])[(k << 1) + 1] = -1;
        ofs += 80;
        idx += 8;
    }
    i2 = 0;
    total = total / 12;
    while (i2 < total && *(s16*)((char*)data + i2 * 12 + 6) > -1) {
        *(s8*)((char*)lbl_80382238[3] + *(s16*)((char*)data + i2 * 12 + 6)) =
            (s8)*(s16*)((char*)data + i2 * 12 + 4);
        mapInitSetRects((s16*)((char*)lbl_80382238[1] + *(s16*)((char*)data + i2 * 12 + 6) * 10),
                        (u8*)((char*)lbl_80382238[4] + *(s16*)((char*)data + i2 * 12 + 6) * 64),
                        *(s16*)((char*)data + i2 * 12), *(s16*)((char*)data + i2 * 12 + 2),
                        *(s16*)((char*)data + i2 * 12 + 6));
        ((s16*)lbl_80382238[2])[*(s16*)((char*)data + i2 * 12 + 6) << 1] =
            *(s16*)((char*)data + i2 * 12 + 8);
        ((s16*)lbl_80382238[2])[(*(s16*)((char*)data + i2 * 12 + 6) << 1) + 1] =
            *(s16*)((char*)data + i2 * 12 + 0xa);
        i2++;
    }
    lbl_803DCEA4 = 0;
    lbl_803DCEB6 = 0;
    lbl_803DCEB4 = 0;
    mm_free(data);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void mapFn_80057d24(int a, int b, int* o0, int* o1, int* o2, int* o3, int f1, int f2, int idx)
{
    int base;
    s16* e2;
    int aa, bb;
    int ptr0;
    int tbl, tbl2;
    int index;
    int idx2;
    u32 v, v2;
    int cellVal;

    if (idx == -1) {
        o0[0] = -1; o0[1] = 1; o0[2] = -1; o0[3] = 1;
        o1[0] = 0; o1[1] = 0; o1[2] = 0; o1[3] = -1;
        o2[0] = 0; o2[1] = 0; o2[2] = 0; o2[3] = -1;
        o3[0] = 0; o3[1] = 0; o3[2] = 0; o3[3] = -1;
        if (f1 != 0)
            o0[3] = -2;
        return;
    }
    base = lbl_80382238[1];
    e2 = (s16*)(base + lbl_8038224C[idx].field_4 * 10);
    aa = a - e2[0];
    bb = b - e2[2];
    ptr0 = lbl_8038224C[idx].field_0;
    if (idx == -1) {
        o0[0] = -1; o0[1] = 1; o0[2] = -1; o0[3] = 1;
        o1[0] = 0; o1[1] = 0; o1[2] = 0; o1[3] = -1;
        o2[0] = 0; o2[1] = 0; o2[2] = 0; o2[3] = -1;
        o3[0] = 0; o3[1] = 0; o3[2] = 0; o3[3] = -1;
        if (f1 != 0)
            o0[3] = -2;
        return;
    }
    if (f2 != 0) {
        tbl = *(int*)(ptr0 + 0x30);
        tbl2 = *(int*)(ptr0 + 0x34);
    } else {
        tbl = *(int*)(ptr0 + 0x14);
        tbl2 = *(int*)(ptr0 + 0x2c);
    }
    index = aa + bb * *(s16*)ptr0;
    idx2 = index * 2;
    if (f1 == 0) {
        v = ((int*)tbl)[idx2];
        o0[0] = ((v >> 12) & 0xf) - 7;
        o0[2] = ((v >> 8) & 0xf) - 7;
        o0[1] = ((v >> 4) & 0xf) - 7;
        o0[3] = (v & 0xf) - 7;
        o1[0] = (v >> 28) - 7;
        o1[2] = ((v >> 24) & 0xf) - 7;
        o1[1] = ((v >> 20) & 0xf) - 7;
        o1[3] = ((v >> 16) & 0xf) - 7;
        v2 = ((int*)tbl)[idx2 + 1];
        o2[0] = ((v2 >> 12) & 0xf) - 7;
        o2[2] = ((v2 >> 8) & 0xf) - 7;
        o2[1] = ((v2 >> 4) & 0xf) - 7;
        o2[3] = (v2 & 0xf) - 7;
        o3[0] = (v2 >> 28) - 7;
        o3[2] = ((v2 >> 24) & 0xf) - 7;
        o3[1] = ((v2 >> 20) & 0xf) - 7;
        o3[3] = ((v2 >> 16) & 0xf) - 7;
    } else {
        o0[0] = 0; o0[1] = -1; o0[2] = 0; o0[3] = -1;
        o1[0] = 0; o1[1] = -1; o1[2] = 0; o1[3] = -1;
        o2[0] = 0; o2[1] = -1; o2[2] = 0; o2[3] = -1;
        o3[0] = 0; o3[1] = -1; o3[2] = 0; o3[3] = -1;
        cellVal = *(int*)(*(int*)(ptr0 + 0xc) + (idx2 >> 1) * 4) & 0x7f;
        if (cellVal != 127) {
            v2 = ((int*)tbl2)[f1 + cellVal * 4 - 1];
            o0[0] = ((v2 >> 12) & 0xf) - 7;
            o0[2] = ((v2 >> 8) & 0xf) - 7;
            o0[1] = ((v2 >> 4) & 0xf) - 7;
            o0[3] = (v2 & 0xf) - 7;
            o1[0] = (v2 >> 28) - 7;
            o1[2] = ((v2 >> 24) & 0xf) - 7;
            o1[1] = ((v2 >> 20) & 0xf) - 7;
            o1[3] = ((v2 >> 16) & 0xf) - 7;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mapCoordsToId(int x, int z, int layerIdx)
{
    int x0, z0;
    int x1;
    s8* layers;
    s16* rects;
    u8* bits;
    int id;
    int layer;
    int n;
    int idx;

    layer = curMapLayer + (&lbl_803DB624)[layerIdx];
    rects = (s16*)lbl_80382238[1];
    bits = (u8*)lbl_80382238[4];
    id = 0;
    layers = (s8*)lbl_80382238[3];
    for (n = 0; n < 64; n++) {
        if (layer == layers[0]) {
            x0 = rects[0];
            if (x >= x0) {
                x1 = rects[1];
                if (x <= x1) {
                    z0 = rects[2];
                    if (z >= z0 && z <= rects[3]) {
                        idx = (x - x0) + (z - z0) * ((x1 - x0) + 1);
                        if ((1 << (idx & 7)) & bits[idx >> 3])
                            return id;
                    }
                }
            }
        }
        bits += 0x40;
        id++;
        if (layer == layers[1]) {
            x0 = rects[5];
            if (x >= x0) {
                x1 = rects[6];
                if (x <= x1) {
                    z0 = rects[7];
                    if (z >= z0 && z <= rects[8]) {
                        idx = (x - x0) + (z - z0) * ((x1 - x0) + 1);
                        if ((1 << (idx & 7)) & bits[idx >> 3])
                            return id;
                    }
                }
            }
        }
        rects += 10;
        bits += 0x40;
        layers += 2;
        id++;
    }
    return -1;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_8030E5D4[];

#pragma scheduling off
#pragma peephole off
void fn_8005A8A4(f32* planes, int count)
{
    int k;
    int j;
    int bi;
    f32 best;
    f32 v;

    for (k = 0; k < count; k++) {
        best = lbl_803DEBCC;
        j = 0;
        while (j < 24) {
            v = planes[0] * lbl_8030E5D4[j++];
            v += planes[1] * lbl_8030E5D4[j++];
            v += planes[2] * lbl_8030E5D4[j++];
            if (best < v) {
                best = v;
                bi = j - 3;
            }
        }
        switch (bi) {
        case 0:
            ((u8*)planes)[16] = 0;
            break;
        case 3:
            ((u8*)planes)[16] = 2;
            break;
        case 6:
            ((u8*)planes)[16] = 5;
            break;
        case 9:
            ((u8*)planes)[16] = 7;
            break;
        case 0xc:
            ((u8*)planes)[16] = 1;
            break;
        case 0xf:
            ((u8*)planes)[16] = 3;
            break;
        case 0x12:
            ((u8*)planes)[16] = 4;
            break;
        case 0x15:
            ((u8*)planes)[16] = 6;
            break;
        }
        planes += 5;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int mapRectFn_8005a728(int bx, int bz, char* obj)
{
    f32 a1, a2, b1, b2, c1, c2;
    f32 p3;
    f32 fx, fz, x2, z2, y0, y1;
    f32 v;
    f32* plane;
    int i;
    int j;
    int hit;

    fx = gMapBlockWorldSize * (f32)bx;
    fz = gMapBlockWorldSize * (f32)bz;
    x2 = gMapBlockWorldSize + fx;
    z2 = gMapBlockWorldSize + fz;
    if (obj) {
        y0 = (f32)*(s16*)(obj + 0x8a);
        y1 = (f32)*(s16*)(obj + 0x8c);
    } else {
        y0 = (&lbl_803DEBCC)[8];
        y1 = (&lbl_803DEBCC)[9];
    }
    plane = (f32*)gViewFrustumPlanes;
    for (i = 0; i < 5; i++) {
        f32 p0 = plane[0];
        f32 p1 = plane[1];
        f32 p2 = plane[2];
        p3 = plane[3];
        j = 0;
        hit = 0;
        a1 = fx * p0;
        a2 = x2 * p0;
        b1 = fz * p2;
        b2 = z2 * p2;
        c1 = y0 * p1;
        c2 = y1 * p1;
        while (j < 8 && hit == 0) {
            if (j & 1)
                v = a1;
            else
                v = a2;
            if (j & 2)
                v += b1;
            else
                v += b2;
            if (j & 4)
                v += c1;
            else
                v += c2;
            v += p3;
            if (v > lbl_803DEBCC)
                hit = 1;
            j++;
        }
        if (j == 8 && hit == 0)
            return 0;
        plane += 5;
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void defStartFn_8005972c(char* p, u32* tbl, int idx, int flag)
{
    char* cur;
    int count;
    int pos;
    u8 found;
    u32 mask;
    int* q;
    int j;
    int m;
    int v;
    s16 t;
    int step;
    int n2;

    found = 0;
    mask = 0;
    cur = *(char**)(p + 0x20);
    count = *(u16*)(p + 8);
    if (count != 0) {
        pos = 0;
        if (flag == 0) {
            tbl[0x21] = -1;
            tbl[0] = -1;
            tbl[1] = -1;
            tbl[2] = -1;
            tbl[3] = -1;
            tbl[4] = -1;
            tbl[5] = -1;
            tbl[6] = -1;
            tbl[7] = -1;
            tbl[8] = -1;
            tbl[9] = -1;
            tbl[10] = -1;
            tbl[11] = -1;
            tbl[12] = -1;
            tbl[13] = -1;
            tbl[14] = -1;
            tbl[15] = -1;
            tbl[16] = -1;
            tbl[17] = -1;
            tbl[18] = -1;
            tbl[19] = -1;
            tbl[20] = -1;
            tbl[21] = -1;
            tbl[22] = -1;
            tbl[23] = -1;
            tbl[24] = -1;
            tbl[25] = -1;
            tbl[26] = -1;
            tbl[27] = -1;
            tbl[28] = -1;
            tbl[29] = -1;
            tbl[30] = -1;
            tbl[31] = -1;
        }
        for (; pos < count; ) {
            if (flag != 0) {
                if (*(s16*)cur == 110)
                    (*(void (*)(char*))(*(int*)(*gRomCurveInterface + 0xc)))(cur);
                if (*(s16*)cur == 5)
                    (*(void (*)(char*))(*(int*)(*gCheckpointInterface + 0xc)))(cur);
            } else {
                t = *(s16*)cur;
                if (t == 110 || t == 5) {
                    if (t == 110)
                        (*(void (*)(char*))(*(int*)(*gRomCurveInterface + 8)))(cur);
                    else
                        (*(void (*)(char*))(*(int*)(*gCheckpointInterface + 8)))(cur);
                    if (found == 0) {
                        tbl[0x21] = (int)cur - *(int*)(p + 0x20);
                        found = 1;
                    }
                } else if (*(u8*)(cur + 4) & 0x10) {
                    if ((mask & (1 << *(u8*)(cur + 6))) == 0) {
                        tbl[*(u8*)(cur + 6)] = (int)cur - *(int*)(p + 0x20);
                        mask |= 1 << *(u8*)(cur + 6);
                    }
                }
            }
            step = *(u8*)(cur + 2) * 4;
            pos += step;
            cur += step;
        }
        if (flag == 0) {
            m = count;
            v = tbl[0x21];
            if (v != -1 && v < count)
                m = v;
            j = 0;
            q = (int*)tbl;
            for (n2 = 0; n2 < 4; n2++) {
                v = q[0];
                if (v != -1 && v < m)
                    m = v;
                v = q[1];
                if (v != -1 && v < m)
                    m = v;
                v = q[2];
                if (v != -1 && v < m)
                    m = v;
                v = q[3];
                if (v != -1 && v < m)
                    m = v;
                v = q[4];
                if (v != -1 && v < m)
                    m = v;
                v = q[5];
                if (v != -1 && v < m)
                    m = v;
                v = q[6];
                if (v != -1 && v < m)
                    m = v;
                v = q[7];
                if (v != -1 && v < m)
                    m = v;
                q += 8;
                j += 7;
            }
            tbl[0x22] = m;
            v = tbl[0x21];
            if (v != -1)
                tbl[0x20] = v;
            else
                tbl[0x20] = count;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DEBB8;
extern f32 lbl_803DEBD4;
extern f32 lbl_803DEBD8;
extern f32 lbl_803DEBDC;
extern f32 Vec_distance(f32* a, f32* b);
extern void Camera_ProjectWorldSphere(f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY,
                                      f32* outZ, f32* outRadiusX, f32* outRadiusY, f32* outDepth);

#pragma scheduling off
#pragma peephole off
int objUpdateOpacity(char* obj)
{
    u8 op;
    char* ptr;
    int alpha;
    f32 range;
    f32 d;
    f32 near;
    int* player;
    u8 i;
    f32 o1, o2, o3;
    f32 sz;
    f32 o5, o6;
    f32 prod;

    op = *(u8*)(obj + 0x36);
    if (op == 0) {
        *(u8*)(obj + 0x37) = 0;
        return 0;
    }
    ptr = *(char**)(obj + 0x4C);
    if (ptr != 0 && (*(u8*)(ptr + 5) & 1)) {
        *(u8*)(obj + 0x37) = (u8)(((op + 1) * 255) >> 8);
    } else {
        range = *(f32*)(obj + 0x40);
        if (range < lbl_803DEBB8) {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        player = Obj_GetPlayerObject();
        if (ptr != 0 && (*(u8*)(ptr + 5) & 2) && player != 0) {
            d = Vec_distance((f32*)(obj + 0x18), (f32*)((char*)player + 0x18));
        } else {
            d = Camera_DistanceToCurrentViewPosition(*(f32*)(obj + 0x18), *(f32*)(obj + 0x1c),
                                                     *(f32*)(obj + 0x20));
        }
        if (d > range) {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        alpha = 255;
        near = range - lbl_803DEBD4;
        if (d > near) {
            range = range - near;
            d = d - near;
            alpha = (int)(lbl_803DEBD8 * (lbl_803DEBDC - d / range));
        }
        Camera_ProjectWorldSphere(*(f32*)(obj + 0x18) - playerMapOffsetX, *(f32*)(obj + 0x1c),
                                  *(f32*)(obj + 0x20) - playerMapOffsetZ,
                                  *(f32*)(obj + 0xa8) * *(f32*)(obj + 8),
                                  &o1, &o2, &o3, &sz, &o5, &o6);
        sz = __fabs(sz);
        sz = sz * gMapBlockWorldSize;
        if (sz < (&lbl_803DEBCC)[5]) {
            *(u8*)(obj + 0x37) = 0;
            return 0;
        }
        if (sz < (&lbl_803DEBCC)[7]) {
            alpha = (int)(((f32)alpha * (sz - (&lbl_803DEBCC)[5])) / (&lbl_803DEBCC)[6]);
        }
        *(u8*)(obj + 0x37) = (u8)((alpha * (*(u8*)(obj + 0x36) + 1)) >> 8);
    }
    if (*(u8*)(obj + 0x37) == 0) {
        return 0;
    } else {
        prod = *(f32*)(obj + 0xa8) * *(f32*)(obj + 8);
        for (i = 0; i < 5; i++) {
            f32* plane = (f32*)(gViewFrustumPlanes + i * 20);
            if (*(f32*)(obj + 0x1c) * plane[1] +
                    plane[0] * (*(f32*)(obj + 0x18) - playerMapOffsetX) +
                    plane[2] * (*(f32*)(obj + 0x20) - playerMapOffsetZ) + plane[3] + prod <
                lbl_803DEBCC)
                return 0;
        }
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern int objShouldUnload(char* obj);
extern void Obj_FreeObject(char* obj);
extern int getLoadedFileFlags(int file);
extern int SaveGame_findTransientMapBit(int mapId, int bit);
extern void mapInstantiateObjects(char* page, int mapId, int bit, char* obj);
extern void mapClearBit(int mapId, int bit);
extern void Obj_SetupObject(u32 setup, int a, int b, int c, char* d);

#pragma scheduling off
#pragma peephole off
void mapLoadUnloadObjects(int flag)
{
    char* base;
    s16 count;
    int i;
    int n;
    s16 list[40];
    s16* q;
    int k;
    int* tp;
    char* obj;
    char* fp;
    int unload;
    u32 bits;
    int b;
    int bit;
    u32 cur;
    u32 end;
    u32 o;
    u8* bp;
    u8 m;
    int vis;
    int idx;

    base = (char*)lbl_8037E0C0;
    count = 0;
    tp = (int*)(base + 0x41E0);
    for (i = 0; i < 5; i++) {
        q = (s16*)(*tp + 0x594);
        for (k = 0; k < 3; k++) {
            s16 id = *q;
            if (id >= 0 && id < 80 && *(void**)(base + 0x83A8 + id * 4) != 0) {
                s16 dup = 0;
                s16* w = list;
                int j2;
                for (j2 = 0; j2 < count; j2++) {
                    if (*w == *q) {
                        dup = 1;
                        break;
                    }
                    w++;
                }
                if (dup == 0)
                    list[count++] = id;
            }
            q++;
        }
        tp++;
    }
    {
        int* objs = ObjList_GetObjects(&i, &n);
        while (i < n) {
            obj = (char*)objs[i];
            fp = *(char**)(obj + 0x4C);
            i++;
            unload = 0;
            if (*(s8*)(obj + 0xAC) > -1) {
                u8 fl = *(u8*)(fp + 4);
                if (!(fl & 2)) {
                    if (fl & 0x10) {
                        if (*(s16*)(obj + 0x44) > -1 && objShouldUnload(obj)) {
                            unload = 1;
                        } else if (*(s8*)(obj + 0xAC) < 80 &&
                                   *(void**)(base + 0x83A8 + *(s8*)(obj + 0xAC) * 4) == 0) {
                            unload = 1;
                        }
                    } else {
                        if (*(s16*)(obj + 0x44) > -1 && objShouldUnload(obj)) {
                            unload = 1;
                        } else if (*(s8*)(obj + 0xAC) < 80 &&
                                   *(s8*)(obj + 0xAC) != lbl_803DCEC8) {
                            unload = 1;
                        }
                    }
                }
            }
            if (unload) {
                char* page = *(char**)(base + 0x83A8 + *(s8*)(obj + 0xAC) * 4);
                if (page != 0) {
                    s16 tbit = *(s16*)(obj + 0xB2);
                    if (tbit >= 0 && tbit >= 0) {
                        u8* bb = *(u8**)(page + 0x10);
                        int ix = tbit >> 3;
                        *(s8*)(bb + ix) = bb[ix] & ~(1 << (tbit & 7));
                    }
                }
                if (*(s16*)(obj + 0x46) == 0x72) {
                    s8 mid = *(s8*)(obj + 0xAC);
                    s16 j3 = 0;
                    s16* w2 = list;
                    for (j3 = 0; j3 < count; j3++) {
                        if (mid == *w2)
                            break;
                        w2++;
                    }
                }
                Obj_FreeObject(obj);
                i--;
                n--;
            }
        }
    }
    if (getLoadedFileFlags(lbl_803DCEC8) == 0) {
        for (i = 0; i < 80; i++) {
            if (*(int*)(base + i * 4 + 0x83A8) != 0) {
                bits = (*(u32 (*)(int))(*(int*)(*gMapEventInterface + 0x5c)))(i);
                if (bits != 0) {
                    b = 0;
                    while (bits != 0) {
                        if ((bits & 1) && (s8)SaveGame_findTransientMapBit(i, b) == -1) {
                            mapInstantiateObjects(*(char**)(base + i * 4 + 0x83A8), i, b, 0);
                            mapClearBit(i, b);
                        }
                        bits >>= 1;
                        b++;
                    }
                }
            }
        }
        for (i = 0; i < count; i++) {
            int id2 = list[i];
            if (lbl_803DCEC8 == id2) {
                char* page = *(char**)(base + id2 * 4 + 0x83A8);
                if (page != 0) {
                    m = 1;
                    bit = 0;
                    cur = *(u32*)(page + 0x20);
                    bp = *(u8**)(page + 0x10);
                    end = cur + *(int*)(base + id2 * 0x8C + 0x4290);
                    while (cur < end) {
                        o = cur;
                        if ((*bp & m) == 0 && objShouldLoad(cur, 0, list[i]) != 0) {
                            if (bit >= 0) {
                                char* pg = *(char**)(base + list[i] * 4 + 0x83A8);
                                int ix2 = bit >> 3;
                                int msk = 1 << (bit & 7);
                                *(s8*)(*(int*)(pg + 0x10) + ix2) =
                                    *(u8*)(*(int*)(pg + 0x10) + ix2) & ~msk;
                                *(s8*)(*(int*)(pg + 0x10) + ix2) =
                                    *(u8*)(*(int*)(pg + 0x10) + ix2) | msk;
                            }
                            Obj_SetupObject(o, 1, list[i], bit, 0);
                        }
                        bit++;
                        m = (u8)(m << 1);
                        if (m == 0) {
                            bp++;
                            while (*bp == -1) {
                                bit += 8;
                                cur += *(u8*)(o + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                cur += *(u8*)(cur + 2) * 4;
                                o = cur;
                                bp++;
                            }
                            m = 1;
                        }
                        cur += *(u8*)(o + 2) * 4;
                    }
                }
            }
        }
        {
            int* objs2 = (int*)ObjGroup_GetObjects(6, &n);
            for (i = 0; i < n; i++) {
                char* obj2 = (char*)objs2[i];
                u32 mid2 = *(u8*)(obj2 + 0x34);
                char** slot = (char**)(base + mid2 * 4 + 0x83A8);
                char* page2 = *slot;
                if (page2 != 0) {
                    s8 lp = *(s8*)(obj2 + 0x35) + 1;
                    bit = 0;
                    cur = *(u32*)(page2 + 0x20);
                    end = cur + *(int*)(base + mid2 * 0x8C + 0x4290);
                    bits = (*(u32 (*)(u32))(*(int*)(*gMapEventInterface + 0x5c)))(mid2);
                    if (bits != 0) {
                        b = 0;
                        while (bits != 0) {
                            if ((bits & 1) && (s8)SaveGame_findTransientMapBit(mid2, b) == -1) {
                                mapInstantiateObjects(page2, mid2, b, obj2);
                            }
                            bits >>= 1;
                            mapClearBit(mid2, b);
                            b++;
                        }
                    }
                    while (cur < end) {
                        if (bit < 0) {
                            vis = 0;
                        } else {
                            char* pg2 = *slot;
                            idx = bit >> 3;
                            if (idx < 0xc4) {
                                vis = 1;
                                if (((1 << (bit & 7)) &
                                     *(s8*)(*(int*)(pg2 + 0x10) + idx)) == 0)
                                    vis = 0;
                            } else {
                                vis = 0;
                            }
                        }
                        if (vis == 0 && objShouldLoad(cur, lp, mid2) != 0) {
                            if (bit >= 0) {
                                char* pg3 = *slot;
                                int ix3 = bit >> 3;
                                int msk3 = 1 << (bit & 7);
                                *(s8*)(*(int*)(pg3 + 0x10) + ix3) =
                                    *(u8*)(*(int*)(pg3 + 0x10) + ix3) & ~msk3;
                                *(s8*)(*(int*)(pg3 + 0x10) + ix3) =
                                    *(u8*)(*(int*)(pg3 + 0x10) + ix3) | msk3;
                            }
                            Obj_SetupObject(cur, 1, mid2, bit, obj2);
                        }
                        bit++;
                        cur += *(u8*)(cur + 2) * 4;
                    }
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern int* gObjectTriggerInterface;
extern int* gWaterfxInterface;
extern int* gProjgfxInterface;
extern int* gModgfxInterface;
extern int* gExpgfxInterface;
extern int* gPartfxInterface;
extern int* gSky2Interface;
extern int* gSHthorntailAnimationInterface;
extern int* gCameraInterface;
extern int lbl_803DCDD0;
extern int lbl_803DCDD4;
extern int lbl_803DCDC8;
extern int lbl_803DCDCC;
extern f32 lbl_803DCED0;
extern f32 lbl_803DCECC;
extern int lbl_803DCEC0;
extern u8 lbl_803DCE04;
extern u8 bEnableBlurFilter;
extern u8 bEnableMotionBlur;
extern f32 lbl_803DB62C;
extern int lbl_803DCE00;
extern u8 lbl_803DCEBD;
extern f32 lbl_803DEBD0;
extern void mapInitFn_80069990(void);
extern void mapInitFn_8006fccc(void);
extern void setSaveGameLoadingFlag(void);
extern void clearSaveGameLoadingFlag(void);
extern void trackIntersect(void);
extern void mapSetupPlayer(void);
extern int SaveGame_getCamActionNo(void);
extern u8* saveGameGetEnvState(void);
extern void getEnvfxActImmediately(void* obj, void* target, int effectId, int flags);
extern void getEnvfxAct(void* obj, void* source, int actId, int flags);
extern void skyFn_80088c94(int idx, u8 on);
extern void skyFn_80088e54(f32 a, int on);
extern void Pause_SetDisabled(int);
extern void Pause_ResetMenuFrameCounter(void);

#pragma scheduling off
#pragma peephole off
void beginLoadingMap(void)
{
    char* base;
    int i;
    int j;
    u8* a;
    u8* b;
    int k2, k3;
    int mapKind;
    f32* p;
    f32 px, py, pz;
    int* cam;
    char* player;
    u8* env;
    int bo;
    char buf[0x110];

    base = (char*)lbl_8037E0C0;
    if (lbl_803DCEB8 == -1) {
        lbl_803DCEB8 = -2;
        lbl_803DCDE0 = 8;
    }
    (*(void (*)(void))(*(int*)(*gObjectTriggerInterface + 4)))();
    mapInitFn_80069990();
    for (i = 0; i < 5; i++) {
        a = *(u8**)(base + 0x41F4 + i * 4);
        b = *(u8**)(base + 0x41E0 + i * 4);
        for (j = 0; j < 256; j++) {
            a[j] = 0xFF;
            b[j * 12 + 9] = 0xFF;
        }
    }
    for (j = 0; j < 64; j++) {
        *(s16*)((char*)lbl_803DCE94 + j * 2) = -1;
        *(int*)((char*)lbl_803DCE9C + j * 4) = 0;
    }
    lbl_803DCE98 = 0;
    lbl_803DCDEC = 0;
    mapKind = (u8)(*(int (*)(void))(*(int*)(*gMapEventInterface + 0x74)))();
    p = (f32*)(*(int (*)(void))(*(int*)(*gMapEventInterface + 0x90)))();
    lbl_803DCDD0 = (int)fastFloorf(p[0] / gMapBlockWorldSize);
    lbl_803DCDD4 = (int)fastFloorf(p[2] / gMapBlockWorldSize);
    *(f32*)(base + 0x8588) = p[0];
    *(f32*)(base + 0x858C) = p[1];
    *(f32*)(base + 0x8590) = p[2];
    *(int*)(base + 0x8594) = 1;
    lbl_803DCDC8 = lbl_803DCDD0 * 640;
    lbl_803DCDCC = lbl_803DCDD4 * 640;
    playerMapOffsetX = (f32)lbl_803DCDC8;
    playerMapOffsetZ = (f32)lbl_803DCDCC;
    lbl_803DCED0 = playerMapOffsetX;
    lbl_803DCECC = playerMapOffsetZ;
    lbl_803DCEC8 = -1;
    lbl_803DCEC4 = lbl_803DCEC4 - 1;
    lbl_803DCEC0 = -1;
    curMapLayer = *((char*)p + 0xd);
    renderFlags = (renderFlags & 0x82008) | 0x489F4;
    lbl_803DCE04 = 0;
    bEnableBlurFilter = 0;
    bEnableMotionBlur = 0;
    lbl_803DB62C = lbl_803DEBCC;
    lbl_803DCE00 = -1;
    setSaveGameLoadingFlag();
    pz = p[2];
    py = p[1];
    px = p[0];
    if (!(renderFlags & 2) || (renderFlags & 0x800)) {
        lbl_803DCE64 = px;
        lbl_803DCE60 = py;
        lbl_803DCE5C = pz;
        renderFlags |= 2;
        if (renderFlags & 0x800)
            doPendingMapLoads();
    }
    renderFlags &= ~4;
    trackIntersect();
    cam = Camera_GetCurrentViewSlot();
    *(f32*)((char*)cam + 0xc) = p[0];
    *(f32*)((char*)cam + 0x10) = p[1];
    *(f32*)((char*)cam + 0x14) = p[2];
    mapSetupPlayer();
    lbl_803DCEBD = 0;
    (*(void (*)(void))(*(int*)(*gWaterfxInterface + 0x1c)))();
    (*(void (*)(void))(*(int*)(*gProjgfxInterface + 4)))();
    (*(void (*)(void))(*(int*)(*gModgfxInterface + 4)))();
    (*(void (*)(void))(*(int*)(*gExpgfxInterface + 4)))();
    (*(void (*)(void))(*(int*)(*gPartfxInterface + 4)))();
    (*(void (*)(void))(*(int*)(*gCloudActionInterface + 0x14)))();
    (*(void (*)(void))(*(int*)(*gCloudActionInterface + 8)))();
    (*(void (*)(void))(*(int*)(*gSky2Interface + 8)))();
    (*(void (*)(void))(*(int*)(*gSHthorntailAnimationInterface + 8)))();
    (*(void (*)(void))(*(int*)(*gNewCloudsInterface + 8)))();
    mapInitFn_8006fccc();
    player = (char*)Obj_GetPlayerObject();
    if (lbl_803DCEB8 == -2 && player != 0 && (mapKind == 0 || mapKind == 1)) {
        s16 cam2 = SaveGame_getCamActionNo();
        if (cam2 != -1) {
            (*(void (*)(int, int, int))(*(int*)(*gCameraInterface + 0x24)))(0, cam2, 1);
        }
        env = saveGameGetEnvState();
        {
            s16 v = *(s16*)(env + 4);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = *(s16*)(env + 6);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = *(s16*)(env + 0xa);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
            v = *(s16*)(env + 0xc);
            if (v != -1)
                getEnvfxActImmediately(player, player, v & 0xFFFF, 0);
        }
        skyFn_80088c94(1, (*(u8*)(env + 0x40) & 2) != 0);
        skyFn_80088c94(2, (*(u8*)(env + 0x40) & 4) != 0);
        skyFn_80088e54(lbl_803DEBCC, (*(u8*)(env + 0x40) & 0x10) != 0);
        if (*(u8*)(env + 0x40) & 1)
            bo = 1;
        else
            bo = 0;
        {
            u8* e2 = saveGameGetEnvState();
            if (bo) {
                renderFlags |= 0x50;
                *(s8*)(e2 + 0x40) = *(u8*)(e2 + 0x40) | 9;
            } else {
                renderFlags &= ~0x50;
                *(s8*)(e2 + 0x40) = *(u8*)(e2 + 0x40) & ~9;
            }
        }
        if (*(u8*)(env + 0x40) & 8)
            bo = 1;
        else
            bo = 0;
        {
            u8* e3 = saveGameGetEnvState();
            if (bo) {
                renderFlags |= 0x40;
                *(s8*)(e3 + 0x40) = *(u8*)(e3 + 0x40) | 8;
            } else {
                renderFlags &= ~0x40;
                *(s8*)(e3 + 0x40) = *(u8*)(e3 + 0x40) & ~8;
            }
        }
        if (*(u8*)(env + 0x40) & 0x20)
            lbl_803DCE00 = 1;
        else
            lbl_803DCE00 = -1;
        *(int*)(buf + 0x30) = 0;
        *(f32*)(buf + 0xc) = lbl_803DEBCC;
        *(f32*)(buf + 0x10) = lbl_803DEBCC;
        *(f32*)(buf + 0x14) = lbl_803DEBCC;
        *(f32*)(buf + 0x18) = lbl_803DEBCC;
        *(f32*)(buf + 0x1c) = lbl_803DEBCC;
        *(f32*)(buf + 0x20) = lbl_803DEBCC;
        {
            s16 a1 = *(s16*)(env + 0xe);
            if (a1 != -1) {
                *(f32*)(buf + 0xc) = (f32)*(int*)(env + 0x14);
                *(f32*)(buf + 0x10) = (f32)*(int*)(env + 0x18);
                *(f32*)(buf + 0x14) = (f32)*(int*)(env + 0x1c);
                getEnvfxAct(buf, player, a1 & 0xFFFF, 0);
            }
            a1 = *(s16*)(env + 0x10);
            if (a1 != -1) {
                *(f32*)(buf + 0xc) = (f32)*(int*)(env + 0x20);
                *(f32*)(buf + 0x10) = (f32)*(int*)(env + 0x24);
                *(f32*)(buf + 0x14) = (f32)*(int*)(env + 0x28);
                getEnvfxAct(buf, player, a1 & 0xFFFF, 0);
            }
            a1 = *(s16*)(env + 0x12);
            if (a1 != -1) {
                *(f32*)(buf + 0xc) = (f32)*(int*)(env + 0x2c);
                *(f32*)(buf + 0x10) = (f32)*(int*)(env + 0x30);
                *(f32*)(buf + 0x14) = (f32)*(int*)(env + 0x34);
                getEnvfxAct(buf, player, a1 & 0xFFFF, 0);
            }
        }
        (*(void (*)(f32))(*(int*)(*gSHthorntailAnimationInterface + 0x28)))(*(f32*)env);
    } else {
        (*(void (*)(f32))(*(int*)(*gSHthorntailAnimationInterface + 0x28)))(lbl_803DEBD0);
        (*(void (*)(int))(*(int*)(*gCloudActionInterface + 0x1c)))(1);
    }
    clearSaveGameLoadingFlag();
    Pause_SetDisabled(0);
    Pause_ResetMenuFrameCounter();
}
#pragma peephole reset
#pragma scheduling reset

extern int mapGetDirIdx(int mapId);
extern void setForceLoadImmediately(void);
extern void clearForceLoadImmediately(void);
extern void loadModelAndAnimTabs(void);
extern int getCurrentDataFile(int id);
extern void setShadowFlag_803db658(int v);
extern void gameTextLoadDir(int dir);
extern char sTrackPiLockedFormat[];
extern int lbl_803DCE88;
extern int lbl_803DCE1C;
extern int* lbl_803DCDE4;
extern int lbl_803DCEB0;
extern s16 lbl_803DCE70;
extern u8 lbl_803DCDED;

#pragma scheduling off
#pragma peephole off
void doPendingMapLoads(void)
{
    char* base;
    u8 waited;
    int gx, gz;
    u32 doLoad;
    int layer;
    int row;
    s16 col;
    int cell;
    int i;
    int slot;
    s16* p13;
    s16* p5;
    s16* p7;
    int cnt;
    int* o1;
    f32 dz;
    s16 recs[1200];
    int oa[4], ob[4], oc[4], od[4];

    base = (char*)lbl_8037E0C0;
    waited = 0;
    if (!(renderFlags & 0x1000)) {
        lbl_803DCED0 = playerMapOffsetX;
        lbl_803DCECC = playerMapOffsetZ;
        if (lbl_803DCEC8 != -1 && lbl_803DCEC8 != lbl_803DCEC4 &&
            (lbl_803DCEC4 = lbl_803DCEC8, lbl_803DCEC8 < 118) &&
            lbl_8030E55C[lbl_803DCEC8] != -1) {
            gameTextLoadDir(lbl_8030E55C[lbl_803DCEC8]);
        }
        if (!(renderFlags & 2) && (getLoadedFileFlags(0) != 0 || lbl_803DCE1C == 0)) {
            lbl_803DCE1C = getLoadedFileFlags(0);
        } else {
            renderFlags &= ~2;
            dz = lbl_803DCE5C - playerMapOffsetZ;
            gx = (int)fastFloorf((lbl_803DCE64 - playerMapOffsetX) / gMapBlockWorldSize);
            gz = (int)fastFloorf(dz / gMapBlockWorldSize);
            {
                u32 t = renderFlags;
                doLoad = t & 0x800;
                renderFlags = t & ~0x800;
            }
            {
                u32 ff = getLoadedFileFlags(0);
                if ((ff & 0xFFEFFFFF) != 0) {
                    if (lbl_803DCEC8 != 38 && lbl_803DCEC8 != 58 && lbl_803DCEC8 != 59 &&
                        lbl_803DCEC8 != 60 && lbl_803DCEC8 != 61 && lbl_803DCEC8 != 62 &&
                        lbl_803DCEC8 != 28) {
                        lbl_803DCE04 = 1;
                    }
                } else {
                    if (lbl_803DCE04 != 0) {
                        lbl_803DCE04 = 0;
                        doLoad = 1;
                    }
                }
            }
            if (gx != 7 || gz != 7 || doLoad != 0 || (renderFlags & 0x4000)) {
                setShadowFlag_803db658(1);
                doNothing_8001F678(1, 0);
                cnt = 0;
                layer = 0;
                {
                    int* bp2 = (int*)(base + 0x41E0);
                    int* ap2 = (int*)(base + 0x41F4);
                    int* cp2 = (int*)(base + 0x41CC);
                    int k8;
                    s8 c;
                    p13 = recs;
                    for (layer = 0; layer < 5; layer++) {
                        s16* ent = (s16*)*bp2;
                        char* g = (char*)*ap2;
                        lbl_803DCE88 = *cp2;
                        cell = 0;
                        row = 0;
                        p5 = p13;
                        for (row = 0; row < 16; row++) {
                            col = 0;
                            p7 = p5;
                            for (k8 = 0; k8 < 8; k8++) {
                                c = g[0];
                                if (c > -1) {
                                    p5[0] = lbl_803DCDD0 + col;
                                    p5[1] = lbl_803DCDD4 + row;
                                    p5[3] = layer;
                                    p5[2] = c;
                                    p5 += 4;
                                    p7 += 4;
                                    p13 += 4;
                                    cnt++;
                                }
                                g[0] = -2;
                                *(s8*)(lbl_803DCE88 + cell) = -1;
                                ent[3] = -3;
                                ent[0] = -1;
                                ent[1] = -1;
                                ent[2] = -1;
                                cell++;
                                col++;
                                c = g[1];
                                if (c > -1) {
                                    p5[0] = lbl_803DCDD0 + col;
                                    p5[1] = lbl_803DCDD4 + row;
                                    p5[3] = layer;
                                    p5[2] = c;
                                    p5 += 4;
                                    p7 += 4;
                                    p13 += 4;
                                    cnt++;
                                }
                                g[1] = -2;
                                *(s8*)(lbl_803DCE88 + cell) = -1;
                                ent[9] = -3;
                                ent[6] = -1;
                                ent[7] = -1;
                                ent[8] = -1;
                                ent += 12;
                                cell++;
                                g += 2;
                                col++;
                            }
                            p5 = p7;
                        }
                        bp2++;
                        ap2++;
                        cp2++;
                    }
                }
                lbl_803DCDD0 = (gx + lbl_803DCDD0) - 7;
                lbl_803DCDD4 = (gz + lbl_803DCDD4) - 7;
                playerMapOffsetX = gMapBlockWorldSize * (f32)lbl_803DCDD0;
                playerMapOffsetZ = gMapBlockWorldSize * (f32)lbl_803DCDD4;
                lbl_803DCDC8 = (int)playerMapOffsetX;
                lbl_803DCDCC = (int)playerMapOffsetZ;
                for (i = 0; i < lbl_803DCDEC; i++) {
                    *(s8*)(base + 0x418C + i * 8 + 6) = 0;
                }
                lbl_803DCEC8 = mapCoordsToId(lbl_803DCDD0 + 7, lbl_803DCDD4 + 7, 0);
                lbl_803DCEC0 = -1;
                if (lbl_803DCEC8 == -1) {
                    int d = mapGetDirIdx(41);
                    setForceLoadImmediately();
                    mapLoadDataFile(d, 32);
                    mapLoadDataFile(d, 35);
                    mapLoadDataFile(d, 48);
                    mapLoadDataFile(d, 43);
                    mapLoadDataFile(d, 33);
                    mapLoadDataFile(d, 42);
                    mapLoadDataFile(d, 47);
                    mapLoadDataFile(d, 36);
                    clearForceLoadImmediately();
                    while (getLoadedFileFlags(0) != 0) {
                        OSReport(sTrackPiLockedFormat, getLoadedFileFlags(0));
                        padUpdate();
                        checkReset();
                        if (waited)
                            waitNextFrame();
                        loadDataFiles();
                        dvdCheckError();
                        if (waited) {
                            mmFreeTick(0);
                            gameTextRun();
                            GXFlush_(1, 0);
                        }
                        if (lbl_803DC950)
                            waited = 1;
                    }
                } else {
                    if (lbl_803DCEC8 != -1) {
                        setForceLoadImmediately();
                        {
                            int m = lbl_803DCEC8;
                            int i2 = 0;
                            char* p2 = base + 0x418C;
                            int cn = lbl_803DCDEC;
                            int k;
                            for (k = 0; k < cn; k++) {
                                if (*(int*)p2 != 0 && m == *(s16*)(p2 + 4))
                                    goto found;
                                p2 += 8;
                                i2++;
                            }
                            i2 = -1;
                        found:
                            slot = i2;
                        }
                        if (slot == -1)
                            slot = mapProcessRomList(lbl_803DCEC8);
                        {
                            int m2 = lbl_803DCEC8;
                            u32 sz = getDataFileSize(0x1f);
                            if (m2 < 0 || m2 >= (int)(sz >> 5)) {
                                lbl_803DCEA4 = 0;
                            } else {
                                int e = lbl_803DCE78;
                                getTabEntry(e, 0x1f, m2 << 5, 0x20);
                                lbl_803DCEA4 = *(u8*)(e + 0x1c);
                            }
                        }
                        *(s8*)(base + slot * 8 + 0x4192) = 1;
                        lbl_803DCEC0 = slot;
                        mapGetDirIdx(lbl_803DCEC8);
                        mapCheckCurBlocks(0);
                        mapLoadDataFile(mapGetDirIdx(lbl_803DCEC8), 38);
                        mapLoadDataFile(mapGetDirIdx(lbl_803DCEC8), 37);
                        mapLoadDataFile(mapGetDirIdx(lbl_803DCEC8), 26);
                        mapLoadDataFile(mapGetDirIdx(lbl_803DCEC8), 27);
                        lbl_803DCDE4 = (int*)getCurrentDataFile(38);
                        lbl_803DCEB0 = 0;
                        {
                            int* p3;
                            for (p3 = lbl_803DCDE4; lbl_803DCDE4 != 0 && *p3 != -1; p3++) {
                                lbl_803DCEB0 = lbl_803DCEB0 + 1;
                            }
                        }
                        lbl_803DCEB0 = lbl_803DCEB0 - 1;
                        {
                            int* tp2 = (int*)(base + 0x41E0);
                            for (i = 0; i < 5; i++) {
                                char* g2 = (char*)*tp2;
                                int t2 = 0;
                                int k2;
                                for (k2 = 0; k2 < 2; k2++) {
                                    g2 += 0x540;
                                    t2 += 7;
                                }
                                tp2++;
                            }
                        }
                        {
                            int d2 = mapGetDirIdx(lbl_803DCEC8);
                            mapLoadDataFile(d2, 32);
                            mapLoadDataFile(d2, 35);
                            mapLoadDataFile(d2, 48);
                            mapLoadDataFile(d2, 43);
                            mapLoadDataFile(d2, 13);
                            mapLoadDataFile(d2, 33);
                            mapLoadDataFile(d2, 42);
                            mapLoadDataFile(d2, 47);
                            mapLoadDataFile(d2, 36);
                            mapLoadDataFile(d2, 14);
                        }
                        loadModelAndAnimTabs();
                        {
                            int* ap3 = (int*)(base + 0x41F4);
                            int* cp3 = (int*)(base + 0x41CC);
                            for (layer = 0; layer < 5; layer++) {
                                char* g3;
                                int zz, xx;
                                s8 cnt2;
                                mapFn_80057d24(lbl_803DCDD0 + 7, lbl_803DCDD4 + 7, oa, ob, oc, od,
                                               layer, 0, slot);
                                g3 = (char*)*ap3;
                                lbl_803DCE88 = *cp3;
                                for (zz = oa[2]; zz <= oa[3]; zz++) {
                                    char* gp = g3 + (zz + 7) * 16 + oa[0];
                                    for (xx = oa[0]; xx <= oa[1]; xx++) {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                for (zz = ob[2]; zz <= ob[3]; zz++) {
                                    char* gp = g3 + (zz + 7) * 16 + ob[0];
                                    for (xx = ob[0]; xx <= ob[1]; xx++) {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                for (zz = oc[2]; zz <= oc[3]; zz++) {
                                    char* gp = g3 + (zz + 7) * 16 + oc[0];
                                    for (xx = oc[0]; xx <= oc[1]; xx++) {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                for (zz = od[2]; zz <= od[3]; zz++) {
                                    char* gp = g3 + (zz + 7) * 16 + od[0];
                                    for (xx = od[0]; xx <= od[1]; xx++) {
                                        gp[7] = -3;
                                        gp++;
                                    }
                                }
                                {
                                    s8 cn2 = 0;
                                    int cell2 = 0;
                                    char* gp2 = g3;
                                    int rr, cc;
                                    for (rr = 0; rr < 16; rr++) {
                                        for (cc = 0; cc < 16; cc++) {
                                            int bx = lbl_803DCDD0 + cc;
                                            int bz = lbl_803DCDD4 + rr;
                                            if (*(s8*)gp2 == -3) {
                                                if (mapLoadBlock(cc, rr, bx, bz, layer) == 0) {
                                                    *gp2 = -2;
                                                } else {
                                                    *(s8*)(lbl_803DCE88 + cell2) = cn2++;
                                                }
                                            }
                                            cell2++;
                                            gp2++;
                                        }
                                    }
                                }
                                ap3++;
                                cp3++;
                            }
                        }
                        clearForceLoadImmediately();
                    }
                }
                {
                    s8 first = 1;
                    int i3 = lbl_803DCDEC - 1;
                    char* p4 = base + 0x418C + i3 * 8;
                    for (; i3 >= 0; i3--) {
                        if (*(s8*)(p4 + 6) == 0) {
                            if (*(int*)p4 != 0) {
                                s16 sl = *(s16*)(p4 + 4);
                                defStartFn_8005972c(*(char**)p4, (u32*)(base + sl * 0x8C + 0x4208),
                                                    sl, 1);
                                mm_free(*(void**)p4);
                                *(int*)(base + 0x83A8 + sl * 4) = 0;
                            }
                            *(int*)p4 = 0;
                            *(s16*)(p4 + 4) = -1;
                        }
                        if (first) {
                            if (*(int*)p4 == 0)
                                lbl_803DCDEC--;
                            else
                                first = 0;
                        }
                        p4 -= 8;
                    }
                }
                {
                    s16* rc = recs;
                    for (i = 0; i < cnt; i++) {
                        s16 mid = rc[2];
                        if (mid >= 0) {
                            *(u8*)(lbl_803DCE8C + mid) = *(u8*)(lbl_803DCE8C + mid) - 1;
                            if (*(u8*)(lbl_803DCE8C + mid) == 0) {
                                char* blk = (char*)*(int*)((char*)lbl_803DCE9C + mid * 4);
                                int off;
                                int j, k;
                                *(s16*)((char*)lbl_803DCE94 + mid * 2) = -1;
                                *(int*)((char*)lbl_803DCE9C + mid * 4) = 0;
                                off = 0;
                                for (j = 0; j < *(u8*)(blk + 0xa2); j++) {
                                    char* ent2 = (char*)(*(int*)(blk + 100) + off);
                                    char* cur2 = ent2;
                                    for (k = 0; k < *(u8*)(ent2 + 0x41); k++) {
                                        if (*(u8*)(cur2 + 0x2a) != 0xFF) {
                                            int ix = *(u8*)(cur2 + 0x2a) * 16 + 12;
                                            u8 c2 = *(u8*)(lbl_803DCE68 + ix);
                                            if (c2 != 0)
                                                *(u8*)(lbl_803DCE68 + ix) = c2 - 1;
                                        }
                                        if (*(u8*)(cur2 + 0x29) != 0)
                                            mapTextureOverrideRelease(*(int*)(cur2 + 0x24),
                                                                      *(u8*)(cur2 + 0x29));
                                        cur2 += 8;
                                    }
                                    off += 0x44;
                                }
                                {
                                    int o2 = 0;
                                    for (j = 0; j < *(u8*)(blk + 0xa0); j++) {
                                        textureFree(*(int*)(*(int*)(blk + 0x54) + o2));
                                        o2 += 4;
                                    }
                                }
                                if (*(int*)(blk + 0x74) != 0)
                                    mm_free(*(void**)(blk + 0x74));
                                if (*(int*)(blk + 0x70) != 0)
                                    mm_free(*(void**)(blk + 0x70));
                                setMapBlockFlag();
                                mm_free(blk);
                            }
                        }
                        rc += 4;
                    }
                }
                lbl_803DCE70 = 0;
                lbl_803DCDED = 0;
            }
            mapLoadUnloadObjects(doLoad);
            lbl_803DCE1C = getLoadedFileFlags(0);
            renderFlags &= ~0x4000;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern s16 lbl_803DCE90;
extern int lbl_803DCE84;

#pragma scheduling off
#pragma peephole off
void mapBlockFn_80059354(int x, int z, s16* out, int layer)
{
    int id;
    int slot;
    int cv3, cv4;
    char* entry;
    s16* pairs;
    s16* rects;
    u32 v;
    int k;

    id = mapCoordsToId(x, z, layer);
    if (id != -1) {
        char* p2 = (char*)lbl_8038224C;
        char* q2 = p2;
        int i2 = 0;
        int cn = lbl_803DCDEC;
        for (k = 0; k < cn; k++) {
            if (*(int*)q2 != 0 && id == *(s16*)(q2 + 4))
                goto found1;
            q2 += 8;
            i2++;
        }
        i2 = -1;
    found1:
        slot = i2;
        if (slot == -1)
            slot = mapProcessRomList(id);
        ((BlockEntry*)lbl_8038224C)[slot].field_6 = (((BlockEntry*)lbl_8038224C)[slot].field_6 & 0xFF) | 0x100;
        entry = (char*)lbl_8038224C[slot].field_0;
        pairs = (s16*)lbl_80382238[2];
        cv3 = *(s8*)&pairs[id * 2];
        cv4 = *(s8*)&pairs[id * 2 + 1];
        out[0] = id;
        out[1] = cv3;
        out[2] = cv4;
        if (cv3 != -1) {
            char* q3 = p2;
            int i3 = 0;
            int cn3 = lbl_803DCDEC;
            for (k = 0; k < cn3; k++) {
                if (*(int*)q3 != 0 && cv3 == *(s16*)(q3 + 4))
                    goto found2;
                q3 += 8;
                i3++;
            }
            i3 = -1;
        found2:
            if (i3 == -1)
                i3 = mapProcessRomList(cv3);
            *(s8*)(p2 + 6 + i3 * 8) = 1;
        }
        if (cv4 != -1) {
            int i4 = 0;
            int cn4 = lbl_803DCDEC;
            for (k = 0; k < cn4; k++) {
                if (*(int*)p2 != 0 && cv4 == *(s16*)(p2 + 4))
                    goto found3;
                p2 += 8;
                i4++;
            }
            i4 = -1;
        found3:
            if (i4 == -1)
                i4 = mapProcessRomList(cv4);
            *(s8*)((char*)lbl_8038224C + 6 + i4 * 8) = 1;
        }
        rects = (s16*)(lbl_80382238[1] + id * 10);
        x = x - rects[0];
        z = z - rects[2];
        v = *(u32*)(*(int*)(entry + 0xc) + (x + z * *(s16*)entry) * 4);
        *(s8*)((char*)out + 8) = (v >> 0x11) & 0x3f;
        *(s8*)((char*)out + 9) = v >> 0x17;
        if (*(s8*)((char*)out + 9) == 0xFF)
            *(s8*)((char*)out + 9) = -1;
        if (*(s8*)((char*)out + 9) == -1) {
            out[3] = -1;
        } else {
            if (*(s8*)((char*)out + 9) >= lbl_803DCE90)
                *(s8*)((char*)out + 9) = lbl_803DCE90 - 1;
            out[3] = *(s8*)((char*)out + 8) + *(u16*)(lbl_803DCE84 + *(s8*)((char*)out + 9) * 2);
            if (out[3] >= *(u16*)(lbl_803DCE84 + lbl_803DCE90 * 2))
                out[3] = *(u16*)(lbl_803DCE84 + lbl_803DCE90 * 2) - 1;
        }
    } else {
        out[0] = -1;
        out[1] = -1;
        out[2] = -1;
        out[3] = -2;
        *(s8*)((char*)out + 9) = -1;
        *(s8*)((char*)out + 8) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int gMapBlockLayerTables[];
extern void* lbl_803DCEA8;
extern int lbl_803DCE74;
extern char sTrackCellCoordFormat[];
extern void fn_80137948(char* fmt, ...);
extern void modelRenderInstrsState_init(int* state, int buf, int s1, int s2);

#pragma scheduling off
#pragma peephole off
void mapDebugRender(int* state)
{
    int bx, bz;
    char* blk;
    int sx, sz;
    int wx, wz;
    int ci;
    s16 y0;
    int y0a;
    f32 cy;
    s16 y1;
    int yy, dy, h;
    int step;
    int row, cx, cz;
    int cell;
    s16 v;
    int n;

    if (lbl_803DCDED != 0) {
        bx = (int)fastFloorf((*(f32*)((char*)lbl_803DCEA8 + 0xc) - playerMapOffsetX) /
                             gMapBlockWorldSize);
        bz = (int)fastFloorf((*(f32*)((char*)lbl_803DCEA8 + 0x14) - playerMapOffsetZ) /
                             gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 16 || bz >= 16) {
            blk = 0;
        } else {
            ci = *(s8*)(gMapBlockLayerTables[0] + bx + bz * 16);
            if (ci < 0 || ci >= lbl_803DCE98) {
                blk = 0;
            } else {
                blk = *(char**)((char*)lbl_803DCE9C + ci * 4);
            }
        }
        sx = (int)(gMapBlockWorldSize * fastFloorf(*(f32*)((char*)lbl_803DCEA8 + 0xc) /
                                                   gMapBlockWorldSize));
        sz = (int)(gMapBlockWorldSize * fastFloorf(*(f32*)((char*)lbl_803DCEA8 + 0x14) /
                                                   gMapBlockWorldSize));
        wx = (int)(*(f32*)((char*)lbl_803DCEA8 + 0xc) - (f32)sx);
        wz = (int)(*(f32*)((char*)lbl_803DCEA8 + 0x14) - (f32)sz);
        if (blk != 0) {
            y0 = *(s16*)(blk + 0x8a);
            y0a = y0;
            if (y0 & 1)
                y0a = y0 - 1;
            cy = *(f32*)((char*)lbl_803DCEA8 + 0x10);
            y1 = *(s16*)(blk + 0x8c);
            if (cy > (f32)y1)
                cy = (f32)(y1 - 1);
            yy = (int)cy;
            dy = yy - y0a;
            h = y1 - y0;
            if (h / 80 < 8)
                step = h / 8;
            else
                step = 80;
            row = dy / step;
            cx = wx / 80;
            cz = wz / 80;
            cell = row * 0x40 + cz * 8 + cx;
            fn_80137948(sTrackCellCoordFormat);
            v = lbl_803DCE70;
            n = v >> 3;
            if (v & 7)
                n = n + 1;
            modelRenderInstrsState_init(state, lbl_803DCE74 + n * cell, v, v);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
