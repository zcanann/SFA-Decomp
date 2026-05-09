#include "ghidra_import.h"
#include "main/dll/LGT/LGTprojectedlight.h"
#include "main/dll/SC/SCtotemlogpuz.h"

extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80017a98();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8005d0ac();
extern int FUN_8007f7c0();
extern byte FUN_80080f2c();
extern undefined4 FUN_80080f5c();
extern undefined4 FUN_80080f60();
extern undefined4 FUN_80080f64();
extern undefined4 FUN_80080f68();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f74();
extern undefined4 FUN_80080f78();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern double FUN_80081014();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801d8480();
extern uint countLeadingZeros();
extern void *Obj_GetPlayerObject(void);
extern void gameTextSetColor(int r,int g,int b,int a);
extern void fn_80016870(int textId);
extern void fn_801F3F18(int obj);
extern uint GameBit_Get(int eventId);
extern int fn_80080204(void);

extern undefined4 DAT_802c2c44;
extern undefined4 DAT_802c2c48;
extern undefined4 DAT_802c2c4c;
extern undefined4 DAT_802c2c50;
extern undefined4 DAT_802c2c54;
extern undefined4 DAT_802c2c58;
extern undefined4 DAT_802c2c5c;
extern undefined4 DAT_802c2c60;
extern undefined4 DAT_802c2c64;
extern undefined4 DAT_803dcd78;
extern undefined4 DAT_803dcd7c;
extern undefined4 DAT_803dcd80;
extern undefined4 DAT_803dcd84;
extern undefined4 DAT_803dcd88;
extern undefined4 DAT_803dcd8c;
extern undefined4* DAT_803dd72c;
extern undefined4* lbl_803DCAAC;
extern undefined4 DAT_803de910;
extern undefined4 DAT_803de914;
extern undefined4 DAT_803de918;
extern undefined4 DAT_803de91c;
extern f64 DOUBLE_803e6b00;
extern f64 DOUBLE_803e6b20;
extern f32 lbl_803DC074;
extern f32 lbl_803DE908;
extern f32 lbl_803DE90C;
extern f32 lbl_803E6B08;
extern f32 lbl_803E6B0C;
extern f32 lbl_803E6B10;
extern f32 lbl_803E6B14;
extern f32 lbl_803E6B18;
extern f32 lbl_803E6B1C;
extern f32 lbl_803E5E70;
extern f32 timeDelta;
extern undefined bRam803dcd79;
extern undefined2 bRam803dcd7a;
extern undefined bRam803dcd7d;
extern undefined2 bRam803dcd7e;
extern undefined bRam803dcd81;
extern undefined2 bRam803dcd82;
extern undefined bRam803dcd85;
extern undefined2 bRam803dcd86;
extern undefined bRam803dcd89;
extern undefined2 bRam803dcd8a;
extern undefined bRam803dcd8d;
extern undefined2 bRam803dcd8e;
extern undefined bRam803de91d;
extern undefined2 bRam803de91e;
extern undefined uRam803de915;
extern undefined2 uRam803de916;
extern undefined uRam803de919;
extern undefined2 uRam803de91a;

/*
 * --INFO--
 *
 * Function: wmlevelcontrol_readParams
 * EN v1.0 Address: TODO
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801F44C0
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wmlevelcontrol_readParams(undefined2 *param_1,int param_2)
{
  float *pfVar1;
  
  *param_1 = 0;
  pfVar1 = *(float **)(param_1 + 0x5c);
  *pfVar1 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x18) << 2 ^ 0x80000000) -
                   DOUBLE_803e6b00);
  *(undefined2 *)(pfVar1 + 1) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)(pfVar1 + 2) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)(pfVar1 + 3) = 0;
  if (*(short *)(pfVar1 + 2) < 1) {
    *(int *)(param_1 + 0x7a) = (int)*(short *)(pfVar1 + 2);
  }
  else {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  pfVar1[4] = *(float *)(param_1 + 6);
  pfVar1[5] = *(float *)(param_1 + 8);
  pfVar1[6] = *(float *)(param_1 + 10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f456c
 * EN v1.0 Address: 0x801F456C
 * EN v1.0 Size: 1528b
 * EN v1.1 Address: 0x801F4550
 * EN v1.1 Size: 1300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f456c(int param_1)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  char cVar10;
  byte bVar11;
  double dVar12;
  
  fVar9 = DAT_802c2c64;
  fVar8 = DAT_802c2c60;
  fVar7 = DAT_802c2c5c;
  fVar6 = DAT_802c2c58;
  fVar5 = DAT_802c2c54;
  fVar4 = DAT_802c2c50;
  fVar3 = DAT_802c2c4c;
  fVar2 = DAT_802c2c48;
  fVar1 = DAT_802c2c44;
  cVar10 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  if (cVar10 != '\a') {
    FUN_8005d0ac(0);
    bVar11 = FUN_80080f2c(0);
    if (bVar11 == 0) {
      FUN_80080f60(1);
      FUN_80080f5c(0x88,0xb7,0xba);
      if ((*(uint *)(param_1 + 0xf4) & 4) == 0) {
        FUN_80080f80(1,1,0);
        *(uint *)(param_1 + 0xf4) = *(uint *)(param_1 + 0xf4) | 4;
      }
      else {
        FUN_80080f80(1,1,1);
      }
      dVar12 = FUN_80081014();
      if ((double)lbl_803E6B08 < dVar12) {
        lbl_803DE908 = lbl_803E6B0C;
        lbl_803DE90C = lbl_803E6B0C;
      }
      lbl_803DE90C = -(lbl_803E6B10 * lbl_803DC074 - lbl_803DE90C);
      if (lbl_803DE90C < lbl_803E6B08) {
        lbl_803DE90C = lbl_803E6B08;
      }
      DAT_803de91c = (byte)(int)(lbl_803DE90C *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)DAT_803dcd84 - (uint)DAT_803dcd80 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,DAT_803dcd80 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      bRam803de91d = (byte)(int)(lbl_803DE90C *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)bRam803dcd85 - (uint)bRam803dcd81 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,bRam803dcd81 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      bRam803de91e = (byte)(int)(lbl_803DE90C *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)bRam803dcd86 - (uint)bRam803dcd82 ^
                                                          0x80000000) - DOUBLE_803e6b20) +
                                (float)((double)CONCAT44(0x43300000,bRam803dcd82 ^ 0x80000000) -
                                       DOUBLE_803e6b20));
      FUN_80080f7c(1,DAT_803de91c,bRam803de91d,bRam803de91e,0x40,0x40);
      DAT_803de918 = (undefined)
                     (int)(lbl_803DE90C *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dcd7c - (uint)DAT_803dcd78 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,DAT_803dcd78 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de919 = (undefined)
                     (int)(lbl_803DE90C *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd7d - (uint)bRam803dcd79 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd79 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de91a = (undefined)
                     (int)(lbl_803DE90C *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd7e - (uint)bRam803dcd7a ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd7a ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      FUN_80080f74(1,DAT_803de918,uRam803de919,uRam803de91a);
      DAT_803de914 = (undefined)
                     (int)(lbl_803DE90C *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)DAT_803dcd8c - (uint)DAT_803dcd88 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,DAT_803dcd88 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de915 = (undefined)
                     (int)(lbl_803DE90C *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd8d - (uint)bRam803dcd89 ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd89 ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      uRam803de916 = (undefined)
                     (int)(lbl_803DE90C *
                           (float)((double)CONCAT44(0x43300000,
                                                    (uint)bRam803dcd8e - (uint)bRam803dcd8a ^
                                                    0x80000000) - DOUBLE_803e6b20) +
                          (float)((double)CONCAT44(0x43300000,bRam803dcd8a ^ 0x80000000) -
                                 DOUBLE_803e6b20));
      FUN_80080f78(1,DAT_803de914,uRam803de915,uRam803de916);
      DAT_803de910 = (undefined)(int)(lbl_803DE90C * lbl_803E6B18 + lbl_803E6B14);
      FUN_80080f68(1);
      FUN_80080f64((double)(lbl_803DE90C * (fVar7 - fVar4) + fVar4),
                   (double)(lbl_803DE90C * (fVar8 - fVar5) + fVar5),
                   (double)(lbl_803DE90C * (fVar9 - fVar6) + fVar6),(double)lbl_803E6B1C);
      FUN_80080f70((double)fVar1,(double)fVar2,(double)fVar3,1);
    }
    else {
      FUN_80080f60(0);
      FUN_80080f68(0);
      FUN_80080f80(7,0,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4b64
 * EN v1.0 Address: 0x801F4B64
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801F4A64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4b64(int param_1)
{
  ObjGroup_RemoveObject(param_1,9);
  FUN_800067c0((int *)0xa8,0);
  FUN_80017698(0xa7f,0);
  FUN_80017698(0x372,1);
  FUN_80017698(0x390,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4bb8
 * EN v1.0 Address: 0x801F4BB8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801F4AB8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4bb8(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: wmlevelcontrol_update
 * EN v1.0 Address: 0x801F44B4
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801F44C0
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wmlevelcontrol_update(int obj)
{
  uint areaId;
  int loadingDone;
  float *state;
  float timer;
  
  Obj_GetPlayerObject();
  state = *(float **)(obj + 0xb8);
  timer = *state;
  if (timer > lbl_803E5E70) {
    gameTextSetColor(0xff,0xff,0xff,0xff);
    fn_80016870(0x42c);
    *state = *state - timeDelta;
    timer = *state;
    if (timer < lbl_803E5E70) {
      *state = lbl_803E5E70;
    }
  }
  if (*(u8 *)(state + 5) == 0) {
    areaId = (*(code *)(*lbl_803DCAAC + 0x40))((int)*(char *)(obj + 0xac));
    areaId = __cntlzw(6 - (areaId & 0xff));
    areaId = areaId >> 5;
    if (((areaId == 0) || (loadingDone = fn_80080204(), loadingDone == 0)) ||
       (areaId = GameBit_Get(0xa7f), areaId == 0)) {
      SCGameBitLatch_UpdateInverted((SCGameBitLatchState *)(state + 4),0x10,-1,-1,0xa7f,0xa6);
      SCGameBitLatch_Update((SCGameBitLatchState *)(state + 4),2,-1,-1,0xa7f,0xa8);
    }
    if (0x3c < *(uint *)(state + 6)) {
      SCGameBitLatch_Update((SCGameBitLatchState *)(state + 4),1,-1,-1,0xada,0xac);
    }
    SCGameBitLatch_Update((SCGameBitLatchState *)(state + 4),0x20,-1,-1,0xcbb,0xc4);
  }
  fn_801F3F18(obj);
  *(uint *)(state + 6) = *(uint *)(state + 6) + 1;
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void wmlevelcontrol_release(void) {}
void wmlevelcontrol_initialise(void) {}
void wmgeneralscales_hitDetect(void) {}
void wmgeneralscales_update(void) {}
void wmgeneralscales_release(void) {}
void wmgeneralscales_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int wmgeneralscales_getExtraSize(void) { return 0x8; }
int wmgeneralscales_func08(void) { return 0x9; }

extern void ObjLink_DetachChild(int *parent, int *child);
#pragma scheduling off
#pragma peephole off
void wmgeneralscales_free(int *obj) { int *p = (int*)obj[0xc8/4]; if (p != NULL) ObjLink_DetachChild(obj, p); }
#pragma peephole reset
#pragma scheduling reset

extern void fn_801F4F88(int *obj);
#pragma scheduling off
#pragma peephole off
int fn_801F4C04(int *obj) { fn_801F4F88(obj); return 0; }
#pragma peephole reset
#pragma scheduling reset
