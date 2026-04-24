#include "ghidra_import.h"
#include "main/dll/FRONT/frontend_control.h"

extern undefined4 FUN_8000bb38();
extern uint FUN_80014e9c();
extern uint FUN_80014f14();
extern int FUN_80119730();
extern undefined4 FUN_80119764();
extern undefined4 FUN_80119794();
extern undefined4 FUN_80119a40();
extern undefined4 FUN_80119b88();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802446f8();
extern int FUN_80246a0c();
extern undefined4 FUN_80246c10();
extern undefined4 FUN_80246dcc();

extern undefined4 DAT_8031b464;
extern undefined4 DAT_8031b470;
extern undefined4 DAT_803a6a10;
extern undefined4 DAT_803a6a5e;
extern undefined4 DAT_803a6a5f;
extern undefined4 DAT_803a6a78;
extern undefined4 DAT_803a6a90;
extern undefined4 DAT_803a7f50;
extern undefined4 DAT_803a7f5c;
extern undefined4 DAT_803a7f68;
extern undefined4 DAT_803a7f88;
extern undefined4 DAT_803de310;
extern undefined4 DAT_803de314;
extern undefined4 DAT_803de324;
extern undefined4 DAT_803de325;
extern undefined4 DAT_803de330;
extern undefined4 DAT_803de33c;
extern undefined4 DAT_803de33d;
extern undefined4 DAT_803de33e;
extern undefined4 DAT_803de6a8;

/*
 * --INFO--
 *
 * Function: FUN_80119cc4
 * EN v1.0 Address: 0x80119C20
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80119CC4
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119cc4(void)
{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  do {
    if (DAT_803a6a5f != '\0') {
      while (DAT_803a6a90 < 0) {
        iVar1 = FUN_80119730();
        uVar3 = *(int *)(iVar1 + 4) + DAT_803a6a78;
        if ((uVar3 - (uVar3 / DAT_803a6a10) * DAT_803a6a10 == DAT_803a6a10 - 1) &&
           ((DAT_803a6a5e & 1) == 0)) {
          FUN_80119a40();
        }
        FUN_80119764(iVar1);
        FUN_80243e74();
        DAT_803a6a90 = DAT_803a6a90 + 1;
        FUN_80243e9c();
      }
    }
    if (DAT_803a6a5f == '\0') {
      uVar2 = FUN_80119794();
    }
    else {
      uVar2 = FUN_80119730();
    }
    FUN_80119a40();
    FUN_80119764(uVar2);
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_80119d90
 * EN v1.0 Address: 0x80119C60
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80119D90
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119d90(void)
{
  if (DAT_803de310 != 0) {
    FUN_80246c10(-0x7fc57058);
    DAT_803de310 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119dcc
 * EN v1.0 Address: 0x80119C9C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80119DCC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119dcc(void)
{
  if (DAT_803de310 != 0) {
    FUN_80246dcc(-0x7fc57058);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80119e00
 * EN v1.0 Address: 0x80119CD0
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x80119E00
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80119e00(int param_1,int param_2)
{
  int iVar1;
  
  if (param_2 == 0) {
    iVar1 = FUN_80246a0c(-0x7fc57058,FUN_80119cc4,0,0x803a8fa8,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  else {
    iVar1 = FUN_80246a0c(-0x7fc57058,FUN_80119b88,param_2,0x803a8fa8,0x1000,param_1,1);
    if (iVar1 == 0) {
      return 0;
    }
  }
  FUN_802446f8((undefined4 *)&DAT_803a7f88,&DAT_803a7f5c,3);
  FUN_802446f8((undefined4 *)&DAT_803a7f68,&DAT_803a7f50,3);
  DAT_803de314 = 1;
  DAT_803de310 = 1;
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80119ec8
 * EN v1.0 Address: 0x80119D90
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80119EC8
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80119ec8(void)
{
  uint uVar1;
  
  if (((DAT_803de33c != 0) || (DAT_803de33d != 0)) &&
     (DAT_803de33e = DAT_803de33e + 1, 0xf < DAT_803de33e)) {
    DAT_803de33c = 0;
    DAT_803de33d = 0;
    DAT_803de33e = 0;
  }
  uVar1 = FUN_80014f14(0);
  if ((uVar1 & 0x10) != 0) {
    if (DAT_803de33d == 0) {
      uVar1 = FUN_80014e9c(0);
      if ((((int)(uVar1 & 0xf000) >> 8 |
           (uVar1 & 0xf00) << 4 | (uVar1 & 0xf) << 8 | (int)(uVar1 & 0xf0) >> 4) &
          (uint)*(ushort *)(&DAT_8031b464 + (uint)DAT_803de33c * 2)) != 0) {
        DAT_803de33c = DAT_803de33c + 1;
        DAT_803de33e = 0;
      }
      if (DAT_803de33c == 5) {
        DAT_803de6a8 = 1;
        FUN_8000bb38(0,0x58);
      }
    }
    if (DAT_803de33c == 0) {
      uVar1 = FUN_80014e9c(0);
      if ((((int)(uVar1 & 0xf000) >> 8 |
           (uVar1 & 0xf00) << 4 | (uVar1 & 0xf) << 8 | (int)(uVar1 & 0xf0) >> 4) &
          (uint)*(ushort *)(&DAT_8031b470 + (uint)DAT_803de33d * 2)) != 0) {
        DAT_803de33d = DAT_803de33d + 1;
        DAT_803de33e = 0;
      }
      if (DAT_803de33d == 5) {
        *(undefined *)(DAT_803de330 + DAT_803de324 * 0x24 + 0x21) = 5;
        DAT_803de325 = 1;
        FUN_8000bb38(0,0x58);
      }
    }
  }
  return;
}
