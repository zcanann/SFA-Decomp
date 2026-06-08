#include "main/audio/sfx_ids.h"
#include "main/dll/magicPlant.h"
#include "main/dll/baddie_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits_types.h"

extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d0();
extern int FUN_80006a10();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a5c();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_8014ccb8();
extern void enemy_free(double param_1,double param_2,ushort *param_3,int param_4,uint param_5,
                       char param_6);
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern double SeekTwiceBeforeRead();
extern undefined4 FUN_80293474();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc920;
extern undefined4 DAT_803dc928;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e3508;
extern f64 DOUBLE_803e3530;
extern f64 DOUBLE_803e3590;
extern f64 DOUBLE_803e35b0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803E34AC;
extern f32 lbl_803E34B8;
extern f32 lbl_803E34E8;
extern f32 lbl_803E34EC;
extern f32 lbl_803E34F0;
extern f32 lbl_803E34F4;
extern f32 lbl_803E34F8;
extern f32 lbl_803E3500;
extern f32 lbl_803E3504;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;
extern f32 lbl_803E3518;
extern f32 lbl_803E351C;
extern f32 lbl_803E3520;
extern f32 lbl_803E3524;
extern f32 lbl_803E3528;
extern f32 lbl_803E352C;
extern f32 lbl_803E3538;
extern f32 lbl_803E353C;
extern f32 lbl_803E3540;
extern f32 lbl_803E3548;
extern f32 lbl_803E354C;
extern f32 lbl_803E3550;
extern f32 lbl_803E3554;
extern f32 lbl_803E3558;
extern f32 lbl_803E355C;
extern f32 lbl_803E3560;
extern f32 lbl_803E3564;
extern f32 lbl_803E3568;
extern f32 lbl_803E356C;
extern f32 lbl_803E3570;
extern f32 lbl_803E3574;
extern f32 lbl_803E3578;
extern f32 lbl_803E357C;
extern f32 lbl_803E3580;
extern f32 lbl_803E3588;
extern f32 lbl_803E358C;
extern f32 lbl_803E3598;
extern f32 lbl_803E359C;
extern f32 lbl_803E35A0;
extern f32 lbl_803E35A4;
extern f32 lbl_803E35A8;
extern f32 lbl_803E35B8;

/*
 * --INFO--
 *
 * Function: FUN_80152ec0
 * EN v1.0 Address: 0x80152EC0
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x80152F40
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152ec0(uint param_1,int param_2)
{
  float fVar1;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E34E8;
  *(undefined4 *)(param_2 + 0x2e4) = 0x29;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x7000;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20000;
  *(float *)(param_2 + 0x308) = lbl_803E34EC;
  *(float *)(param_2 + 0x300) = lbl_803E34F0;
  *(float *)(param_2 + 0x304) = lbl_803E34F4;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E34B8;
  *(float *)(param_2 + 0x314) = lbl_803E34B8;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(float *)(param_2 + 0x32c) = lbl_803E34AC;
  *(float *)(param_1 + 0xa8) = lbl_803E34F8;
  FUN_800068d0(param_1,0xe8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80152f54
 * EN v1.0 Address: 0x80152F54
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80152FD8
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152f54(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if ((param_4 != 0x10) && (param_4 != 0x11)) {
    FUN_80006824(param_1,SFXfox_cough1);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20;
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80152fb4
 * EN v1.0 Address: 0x80152FB4
 * EN v1.0 Size: 932b
 * EN v1.1 Address: 0x8015303C
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80152fb4(ushort *param_1,int param_2)
{
  float fVar1;
  float fVar2;
  undefined2 *puVar3;
  int iVar4;
  uint uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar9;
  float local_38;
  float local_34;
  undefined8 local_30;
  undefined8 local_28;
  
  dVar8 = (double)lbl_803E3514;
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x338));
  iVar4 = (int)(dVar8 * (double)lbl_803DC074 + (double)(float)(local_30 - DOUBLE_803e3530));
  local_28 = (double)(longlong)iVar4;
  *(short *)(param_2 + 0x338) = (short)iVar4;
  FUN_80293474((uint)*(ushort *)(param_2 + 0x338),&local_34,&local_38);
  local_34 = local_34 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x324);
  local_38 = local_38 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x32c);
  if (*(char *)(param_2 + 0x33a) == '\0') {
    dVar9 = (double)*(float *)(param_1 + 8);
    fVar1 = *(float *)(param_2 + 0x324) - *(float *)(*(int *)(param_2 + 0x29c) + 0xc);
    fVar2 = *(float *)(param_2 + 0x32c) - *(float *)(*(int *)(param_2 + 0x29c) + 0x14);
    dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    if (dVar8 <= (double)(lbl_803E3518 * *(float *)(param_2 + 0x2a8))) {
      *(undefined *)(param_2 + 0x33a) = 1;
      *(undefined *)(param_2 + 0x33b) = 0;
    }
  }
  else if (*(char *)(param_2 + 0x33a) == '\x01') {
    dVar7 = (double)lbl_803DC074;
    dVar9 = -(double)(float)((double)lbl_803E351C * dVar7 - (double)*(float *)(param_1 + 8));
    if ((double)(*(float *)(param_2 + 0x328) - lbl_803E3520) < dVar9) {
      local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x33b));
      iVar4 = (int)((double)(float)(local_28 - DOUBLE_803e3530) + dVar7);
      local_30 = (double)(longlong)iVar4;
      *(char *)(param_2 + 0x33b) = (char)iVar4;
      if (100 < *(byte *)(param_2 + 0x33b)) {
        *(undefined *)(param_2 + 0x33b) = 0;
        uVar5 = FUN_80017ae8();
        if ((uVar5 & 0xff) != 0) {
          puVar3 = FUN_80017aa4(0x24,0x6b5);
          *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_1 + 6);
          dVar6 = (double)lbl_803E3510;
          *(float *)(puVar3 + 6) = (float)(dVar6 + (double)*(float *)(param_1 + 8));
          *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_1 + 10);
          *(undefined *)(puVar3 + 2) = 1;
          *(undefined *)((int)puVar3 + 5) = 1;
          *(undefined *)(puVar3 + 3) = 0xff;
          *(undefined *)((int)puVar3 + 7) = 0xff;
          iVar4 = FUN_80017a5c(dVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,puVar3);
          if (iVar4 != 0) {
            *(ushort **)(iVar4 + 0xc4) = param_1;
            FUN_80006824((uint)param_1,SFXfox_cough2);
          }
        }
      }
    }
    else {
      *(undefined *)(param_2 + 0x33a) = 2;
    }
  }
  else {
    dVar9 = (double)(lbl_803E3524 * lbl_803DC074 + *(float *)(param_1 + 8));
    if ((double)*(float *)(param_2 + 0x328) <= dVar9) {
      *(undefined *)(param_2 + 0x33a) = 0;
    }
  }
  *(float *)(param_1 + 0x12) = lbl_803DC078 * (local_34 - *(float *)(param_1 + 6));
  *(float *)(param_1 + 0x14) = lbl_803DC078 * (float)(dVar9 - (double)*(float *)(param_1 + 8));
  *(float *)(param_1 + 0x16) = lbl_803DC078 * (local_38 - *(float *)(param_1 + 10));
  enemy_free((double)lbl_803E3528,(double)lbl_803E352C,param_1,param_2,0xf,'\0');
  *(float *)(param_2 + 0x334) = *(float *)(param_2 + 0x334) - lbl_803DC074;
  if (*(float *)(param_2 + 0x334) <= lbl_803E3500) {
    uVar5 = randomGetRange(0x3c,0x78);
    local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(param_2 + 0x334) = (float)(local_28 - DOUBLE_803e3508);
    FUN_80006824((uint)param_1,SFXen_mazewall);
  }
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - lbl_803DC074;
  if (*(float *)(param_2 + 0x330) <= lbl_803E3500) {
    *(float *)(param_2 + 0x330) = lbl_803E3504;
    FUN_80006824((uint)param_1,SFXfox_bigfallrecover1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153358
 * EN v1.0 Address: 0x80153358
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8015336C
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153358(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float local_18;
  float local_14 [3];
  
  fVar1 = lbl_803E3504;
  *(float *)(param_2 + 0x2ac) = lbl_803E3504;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = lbl_803E3538;
  *(float *)(param_2 + 0x300) = lbl_803E353C;
  fVar2 = lbl_803E352C;
  *(float *)(param_2 + 0x304) = lbl_803E352C;
  *(undefined *)(param_2 + 800) = 1;
  *(float *)(param_2 + 0x314) = fVar2;
  *(undefined *)(param_2 + 0x321) = 3;
  *(float *)(param_2 + 0x318) = fVar2;
  *(undefined *)(param_2 + 0x322) = 1;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined4 *)(param_2 + 0x324) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x328) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_1 + 0x14);
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(float *)(param_2 + 0x330) = fVar1;
  *(float *)(param_2 + 0x334) = fVar1;
  *(float *)(param_2 + 0x2fc) = lbl_803E3540;
  FUN_80293474((uint)*(ushort *)(param_2 + 0x338),local_14,&local_18);
  *(float *)(param_1 + 0xc) =
       local_14[0] * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x324);
  *(float *)(param_1 + 0x14) = local_18 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x32c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153440
 * EN v1.0 Address: 0x80153440
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x80153454
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153440(uint param_1,int param_2,undefined4 param_3,int param_4)
{
  if (*(char *)(param_2 + 0x33b) == '\0') {
    if (param_4 != 0x11) {
      if (param_4 == 0x10) {
        *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
      }
      else {
        *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
        FUN_80006824(param_1,SFXfox_climbgrunt4);
        *(undefined2 *)(param_2 + 0x2b0) = 0;
      }
    }
  }
  else if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x28;
    FUN_80006824(param_1,SFXfox_climbgrunt4);
    *(undefined2 *)(param_2 + 0x2b0) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801534d8
 * EN v1.0 Address: 0x801534D8
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x801534EC
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801534d8(ushort *param_1,undefined4 *param_2)
{
  int iVar1;
  char cVar2;
  float *pfVar3;
  float local_28;
  float local_24;
  float local_20;
  
  pfVar3 = (float *)*param_2;
  if (*(int *)(param_1 + 0x2a) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  }
  if (*(char *)((int)param_2 + 0x33b) != '\0') {
    param_2[0xba] = param_2[0xba] | 0x80;
  }
  if ((param_2[0xb7] & 0x2000) != 0) {
    iVar1 = FUN_80006a10((double)(float)param_2[0xbf],pfVar3);
    if ((((iVar1 != 0) || (pfVar3[4] != 0.0)) &&
        (cVar2 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar3), cVar2 != '\0')) &&
       (cVar2 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)lbl_803E3550,*param_2,param_1,&DAT_803dc920,0xffffffff),
       cVar2 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    FUN_8014d3d0((short *)param_1,param_2,0xf,0);
    local_28 = pfVar3[0x1a] - *(float *)(param_1 + 6);
    local_24 = pfVar3[0x1b] - *(float *)(param_1 + 8);
    local_20 = pfVar3[0x1c] - *(float *)(param_1 + 10);
    FUN_8014ccb8((double)lbl_803E3554,(double)lbl_803E3558,(double)lbl_803E355C,(int)param_1,
                 (int)param_2,&local_28,'\x01');
    param_2[0xc9] = (float)param_2[0xc9] + lbl_803DC074;
    if (lbl_803E3560 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = lbl_803E3548;
    }
  }
  enemy_free((double)lbl_803E3564,(double)lbl_803E3568,param_1,(int)param_2,0xf,'\0');
  param_2[0xca] = (float)param_2[0xca] - lbl_803DC074;
  if ((float)param_2[0xca] <= lbl_803E3548) {
    param_2[0xca] = lbl_803E354C;
    FUN_80006824((uint)param_1,SFXfox_healthgasp1);
  }
  param_2[0xcb] = lbl_803E3548;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153738
 * EN v1.0 Address: 0x80153738
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x801536F4
 * EN v1.1 Size: 656b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153738(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 *param_10)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  char cVar4;
  float *pfVar5;
  undefined8 uVar6;
  undefined auStack_48 [4];
  short asStack_44 [4];
  short asStack_3c [4];
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  
  pfVar5 = (float *)*param_10;
  if (*(char *)((int)param_10 + 0x33b) != '\0') {
    param_10[0xba] = param_10[0xba] | 0x80;
  }
  if ((param_10[0xb7] & 0x80000000) != 0) {
    FUN_80006824((uint)param_9,SFXfox_climbgrunt3);
  }
  if ((((param_10[0xb7] & 0x2000) != 0) &&
      (((iVar3 = FUN_80006a10((double)(lbl_803E356C * (float)param_10[0xbf]),pfVar5), iVar3 != 0
        || (pfVar5[4] != 0.0)) &&
       (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar4 != '\0')))) &&
     (cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)lbl_803E3550,*param_10,param_9,&DAT_803dc920,0xffffffff),
     cVar4 != '\0')) {
    param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
  }
  ObjHits_SetHitVolumeSlot((int)param_9,0xe,1,0);
  iVar3 = param_10[0xa7];
  local_28 = *(float *)(iVar3 + 0xc) - *(float *)(param_9 + 6);
  local_24 = (lbl_803E3570 + *(float *)(iVar3 + 0x10)) - *(float *)(param_9 + 8);
  local_20 = *(float *)(iVar3 + 0x14) - *(float *)(param_9 + 10);
  SeekTwiceBeforeRead(&local_28);
  param_10[0xcb] = (float)param_10[0xcb] + lbl_803DC074;
  if ((param_10[0xd0] != 0) || (lbl_803E3560 < (float)param_10[0xcb])) {
    param_10[0xb9] = param_10[0xb9] | 0x10000;
    fVar1 = lbl_803E3548;
    param_10[0xc9] = lbl_803E3548;
    param_10[0xcb] = fVar1;
  }
  else {
    local_34 = *(float *)(param_9 + 6);
    local_30 = *(float *)(param_9 + 8);
    local_2c = *(float *)(param_9 + 10);
    FUN_80006a68(&local_34,asStack_44);
    local_34 = pfVar5[0x1a];
    local_30 = pfVar5[0x1b];
    local_2c = pfVar5[0x1c];
    uVar6 = FUN_80006a68(&local_34,asStack_3c);
    uVar2 = countLeadingZeros(param_10[0xb7]);
    if (((uVar2 >> 5 & 0x1000000) != 0) &&
       (iVar3 = FUN_80006a64(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             asStack_3c,asStack_44,(undefined4 *)0x0,auStack_48,0), iVar3 == 0)) {
      param_10[0xb9] = param_10[0xb9] | 0x10000;
      fVar1 = lbl_803E3548;
      param_10[0xc9] = lbl_803E3548;
      param_10[0xcb] = fVar1;
    }
  }
  FUN_8014ccb8((double)lbl_803E3554,(double)lbl_803E3558,(double)lbl_803E355C,(int)param_9,
               (int)param_10,&local_28,'\x01');
  enemy_free((double)lbl_803E3564,(double)lbl_803E3568,param_9,(int)param_10,0xf,'\0');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153a80
 * EN v1.0 Address: 0x80153A80
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x80153984
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153a80(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  
  *(float *)(param_2 + 0x2ac) = lbl_803E3574;
  *(undefined4 *)(param_2 + 0x2e4) = 0x1009;
  *(float *)(param_2 + 0x308) = lbl_803E3578;
  *(float *)(param_2 + 0x300) = lbl_803E357C;
  *(float *)(param_2 + 0x304) = lbl_803E3580;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = lbl_803E3554;
  *(float *)(param_2 + 0x314) = lbl_803E3554;
  *(undefined *)(param_2 + 0x321) = 1;
  fVar2 = lbl_803E3568;
  *(float *)(param_2 + 0x318) = lbl_803E3568;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = lbl_803E3548;
  *(float *)(param_2 + 0x324) = lbl_803E3548;
  *(float *)(param_2 + 0x328) = fVar1;
  *(float *)(param_2 + 0x32c) = fVar1;
  *(float *)(param_2 + 0x2fc) = fVar2;
  if (*(short *)(param_1 + 0x46) != 0x7c6) {
    *(undefined *)(param_2 + 0x33b) = 0;
    return;
  }
  *(undefined *)(param_2 + 0x33b) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153b00
 * EN v1.0 Address: 0x80153B00
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x80153A08
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153b00(int param_1,int param_2)
{
  char cVar1;
  
  cVar1 = '\0';
  switch(*(undefined2 *)(param_1 + 0xa0)) {
  case 1:
    cVar1 = '\x01';
    break;
  case 2:
    cVar1 = '\x01';
    break;
  case 3:
    cVar1 = '\x01';
    break;
  case 5:
    if ((*(uint *)(param_2 + 0x2dc) & 0x80000000) != 0) {
      cVar1 = '\n';
    }
  }
  if ((cVar1 != '\0') && ((*(uint *)(param_2 + 0x2dc) & 0x40000000) == 0)) {
    for (; cVar1 != '\0'; cVar1 = cVar1 + -1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x802,0,2,0xffffffff,0);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153be0
 * EN v1.0 Address: 0x80153BE0
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80153AEC
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153be0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar5;
  
  uVar2 = FUN_80017ae8();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_80017aa4(0x24,0x51b);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar5 = (double)lbl_803E3588;
    *(float *)(puVar3 + 6) = (float)(dVar5 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar4 = FUN_80017ae4(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar4 != 0) {
      *(float *)(iVar4 + 0x24) =
           lbl_803E358C * (*(float *)(*(int *)(param_10 + 0x29c) + 0xc) - *(float *)(puVar3 + 4));
      uVar2 = randomGetRange(0xfffffff6,10);
      fVar1 = lbl_803E358C;
      *(float *)(iVar4 + 0x28) =
           lbl_803E358C *
           ((lbl_803E3588 + *(float *)(*(int *)(param_10 + 0x29c) + 0x10) +
            (f32)(s32)(uVar2)) -
           *(float *)(puVar3 + 6));
      *(float *)(iVar4 + 0x2c) =
           fVar1 * (*(float *)(*(int *)(param_10 + 0x29c) + 0x14) - *(float *)(puVar3 + 8));
      *(uint *)(iVar4 + 0xc4) = param_9;
    }
    FUN_80006824(param_9,0x49a);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153db4
 * EN v1.0 Address: 0x80153DB4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x80153C3C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153db4(uint param_1,int param_2,undefined4 param_3,int param_4,undefined4 param_5,
                 int param_6)
{
  if ((*(short *)(param_1 + 0xa0) != 1) || ((*(uint *)(param_2 + 0x2dc) & 0x40000000) == 0)) {
    if (param_4 == 0x10) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
    else {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      if ((int)(uint)*(ushort *)(param_2 + 0x2b0) < param_6) {
        FUN_80006824(param_1,SFXfox_bigfallgrunt1);
        *(undefined2 *)(param_2 + 0x2b0) = 0;
      }
      else {
        FUN_80006824(param_1,SFXfox_bigfallgrunt2);
        *(short *)(param_2 + 0x2b0) = *(short *)(param_2 + 0x2b0) - (short)param_6;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80153e5c
 * EN v1.0 Address: 0x80153E5C
 * EN v1.0 Size: 1608b
 * EN v1.1 Address: 0x80153CE8
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80153e5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  bool bVar1;
  short sVar2;
  int iVar3;
  char cVar5;
  uint uVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar6;
  double dVar7;
  undefined8 uVar8;
  undefined auStack_48 [4];
  short asStack_44 [4];
  short asStack_3c [4];
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) & 0x7f;
  bVar1 = false;
  iVar3 = *(int *)(param_10 + 0x29c);
  local_34 = *(float *)(param_9 + 6) - *(float *)(iVar3 + 0xc);
  local_30 = *(float *)(param_9 + 8) - *(float *)(iVar3 + 0x10);
  local_2c = *(float *)(param_9 + 10) - *(float *)(iVar3 + 0x14);
  dVar7 = SeekTwiceBeforeRead(&local_34);
  if (((double)lbl_803E3598 <= dVar7) ||
     ((*(ushort *)(*(int *)(param_10 + 0x29c) + 0xb0) & 0x1000) != 0)) {
    cVar5 = '\0';
  }
  else {
    local_28 = *(float *)(param_9 + 6);
    local_24 = lbl_803E359C + *(float *)(param_9 + 8);
    local_20 = *(undefined4 *)(param_9 + 10);
    FUN_80006a68(&local_28,asStack_44);
    iVar3 = *(int *)(param_10 + 0x29c);
    local_28 = *(float *)(iVar3 + 0xc);
    local_24 = lbl_803E35A0 + *(float *)(iVar3 + 0x10);
    local_20 = *(undefined4 *)(iVar3 + 0x14);
    uVar8 = FUN_80006a68(&local_28,asStack_3c);
    cVar5 = FUN_80006a64(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_3c,
                         asStack_44,(undefined4 *)0x0,auStack_48,0);
    if (cVar5 != '\0') {
      FUN_8014d3d0(param_9,param_10,0x14,0);
      param_2 = (double)local_2c;
      iVar3 = FUN_80017730();
      sVar2 = (short)iVar3 - *param_9;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      if (sVar2 < 0) {
        sVar2 = -sVar2;
      }
      if (sVar2 < 1000) {
        bVar1 = true;
      }
    }
  }
  if ((*(byte *)(param_10 + 0x33b) & 0x40) == 0) {
    FUN_800067e8((uint)param_9,0x49b,2);
    FUN_8014d4c8((double)lbl_803E35A4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
    *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) | 0x40;
    *(undefined *)(param_10 + 0x33a) = 0;
  }
  else if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (cVar5 == '\0') {
      uVar6 = randomGetRange(2,4);
      uVar6 = uVar6 & 0xff;
      if (uVar6 == 2) {
        uVar6 = 0;
      }
      else if (uVar6 == 4) {
        FUN_80006824((uint)param_9,0x357);
      }
    }
    else if (*(char *)(param_10 + 0x33a) == '\0') {
      if ((param_9[0x50] == 5) || (!bVar1)) {
        uVar6 = 4;
        uVar4 = randomGetRange(1,2);
        *(char *)(param_10 + 0x33a) = (char)uVar4;
      }
      else {
        uVar6 = 5;
        *(undefined *)(param_10 + 0x33a) = (&DAT_803dc928)[*(byte *)(param_10 + 0x33b) & 3];
        *(byte *)(param_10 + 0x33b) = *(char *)(param_10 + 0x33b) + 1U & 0xc3;
      }
    }
    else {
      *(char *)(param_10 + 0x33a) = *(char *)(param_10 + 0x33a) + -1;
      uVar6 = (int)param_9[0x50] & 0xff;
    }
    FUN_8014d4c8((double)lbl_803E35A8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,uVar6,0,0,in_r8,in_r9,in_r10);
  }
  if (param_9[0x50] == 5) {
    dVar7 = (double)*(float *)(param_9 + 0x4c);
    if ((DOUBLE_803e35b0 <= dVar7) &&
       (dVar7 < DOUBLE_803e35b0 +
                (double)(float)((double)*(float *)(param_10 + 0x308) * (double)lbl_803DC074))) {
      FUN_80153be0((double)*(float *)(param_10 + 0x308),DOUBLE_803e35b0,dVar7,param_4,param_5,
                   param_6,param_7,param_8,(uint)param_9,param_10);
      goto LAB_8015407c;
    }
  }
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - lbl_803DC074;
  if (*(float *)(param_10 + 0x324) <= lbl_803E35B8) {
    uStack_14 = randomGetRange(0x96,300);
    *(float *)(param_10 + 0x324) = (f32)(s32)uStack_14
    ;
    FUN_80006824((uint)param_9,SFXwatery_bubble3);
  }
LAB_8015407c:
  FUN_80153b00((int)param_9,param_10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801544a4
 * EN v1.0 Address: 0x801544A4
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x801540A8
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801544a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) & 0xbf;
  if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) && (*(short *)(param_9 + 0xa0) != 1)) {
    FUN_800067e8(param_9,0x49c,2);
    FUN_8014d4c8((double)lbl_803E35A4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
  }
  FUN_80153b00(param_9,param_10);
  return;
}

extern f32 lbl_803E28B0;
extern f32 lbl_803E28BC;
extern f32 lbl_803E28D0;
extern f32 lbl_803E28DC;
extern f32 lbl_803E28E0;
extern f32 lbl_803E28E4;
extern f32 lbl_803E28E8;

#pragma scheduling off
#pragma peephole off
void fn_80153790(int obj, int state, int p3, int msgFlag, int p5, int p6)
{
    if (((GameObject *)obj)->anim.currentMove == 1) {
        if ((((BaddieState *)state)->controlFlags & 0x40000000) != 0) {
            return;
        }
    }
    if (msgFlag == 0x10) {
        ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x20;
    } else {
        ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x8;
        if (p6 > (s32)((BaddieState *)state)->hitCounter) {
            Sfx_PlayFromObject(obj, SFXfox_bigfallgrunt1);
            *(s16 *)&((BaddieState *)state)->hitCounter = 0;
        } else {
            Sfx_PlayFromObject(obj, SFXfox_bigfallgrunt2);
            ((BaddieState *)state)->hitCounter = (u16)(((BaddieState *)state)->hitCounter - p6);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801534D8(int obj, int state)
{
    f32 lblBC;
    f32 lblB0;
    f32 lblD0;

    ((BaddieState *)state)->unk2AC = lbl_803E28DC;
    *(u32 *)&((BaddieState *)state)->unk2E4 = 0x1009;
    ((BaddieState *)state)->unk308 = lbl_803E28E0;
    ((BaddieState *)state)->unk300 = lbl_803E28E4;
    ((BaddieState *)state)->unk304 = lbl_803E28E8;
    ((BaddieState *)state)->unk320 = 0;
    lblBC = lbl_803E28BC;
    *(f32 *)&((BaddieState *)state)->eventFlags = lblBC;
    ((BaddieState *)state)->unk321 = 1;
    lblD0 = lbl_803E28D0;
    ((BaddieState *)state)->unk318 = lblD0;
    ((BaddieState *)state)->unk322 = 0;
    ((BaddieState *)state)->unk31C = lblBC;
    lblB0 = lbl_803E28B0;
    *(f32*)(state + 0x324) = lblB0;
    *(f32*)(state + 0x328) = lblB0;
    *(f32*)(state + 0x32c) = lblB0;
    ((BaddieState *)state)->pathStep = lblD0;
    if (((GameObject *)obj)->anim.seqId == 0x7c6) {
        ((BaddieState *)state)->inWhirlpoolGroup = 1;
    } else {
        ((BaddieState *)state)->inWhirlpoolGroup = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E286C;
extern f32 lbl_803E2894;
extern f32 lbl_803E28B4;
extern f32 lbl_803E28B8;
extern f32 lbl_803E28C0;
extern f32 lbl_803E28C4;
extern f32 lbl_803E28C8;
extern f32 lbl_803E28CC;
extern int lbl_803DBCB8;
extern f32 timeDelta;
extern int Curve_AdvanceAlongPath(int* curve, f32 t);
extern void fn_8014CF7C(int obj, int state, int p3, int p4, f32 f1, f32 f2);
extern void fn_8014C678(int obj, int state, void* vec, f32 f1, f32 f2, f32 f3, int p6);
extern void fn_8014CD1C(int obj, int state, int p3, f32 f1, f32 f2, int p6);

#pragma scheduling off
#pragma peephole off
void fn_80153040(int obj, int state)
{
    int* curve;
    f32 vec[3];

    curve = *(int**)state;
    if (((GameObject *)obj)->anim.hitReactState != NULL) {
        ((ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState)->suppressOutgoingHits = 0;
    }
    if (((BaddieState *)state)->inWhirlpoolGroup != 0) {
        ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x80;
    }
    if ((((BaddieState *)state)->controlFlags & 0x2000) != 0) {
        if (Curve_AdvanceAlongPath(curve, ((BaddieState *)state)->pathStep) != 0 || ((RomCurveWalker *)curve)->unk10 != 0) {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0) {
                if ((*gRomCurveInterface)->initCurve(*(void **)state, (void *)obj, lbl_803E28B8,
                                                     &lbl_803DBCB8, -1) != 0) {
                    ((BaddieState *)state)->controlFlags = ((BaddieState *)state)->controlFlags & ~0x2000;
                }
            }
        }
    }

    fn_8014CF7C(obj, state, 0xf, 0, ((RomCurveWalker *)curve)->unk68, ((RomCurveWalker *)curve)->unk70);

    vec[0] = ((RomCurveWalker *)curve)->unk68 - ((GameObject *)obj)->anim.localPosX;
    vec[1] = ((RomCurveWalker *)curve)->unk6C - ((GameObject *)obj)->anim.localPosY;
    vec[2] = ((RomCurveWalker *)curve)->unk70 - ((GameObject *)obj)->anim.localPosZ;
    fn_8014C678(obj, state, vec, lbl_803E28BC, lbl_803E28C0, lbl_803E28C4, 1);

    *(f32*)(state + 0x324) = *(f32*)(state + 0x324) + timeDelta;
    if (*(f32*)(state + 0x324) > lbl_803E28C8) {
        *(u32 *)&((BaddieState *)state)->unk2E4 = *(u32 *)&((BaddieState *)state)->unk2E4 & 0xfffeffff;
        *(f32*)(state + 0x324) = lbl_803E28B0;
    }

    fn_8014CD1C(obj, state, 0xf, lbl_803E28CC, lbl_803E28D0, 0);

    *(f32*)(state + 0x328) = *(f32*)(state + 0x328) - timeDelta;
    if (*(f32*)(state + 0x328) <= lbl_803E28B0) {
        *(f32*)(state + 0x328) = lbl_803E28B4;
        Sfx_PlayFromObject(obj, SFXfox_healthgasp1);
    }
    *(f32*)(state + 0x32c) = lbl_803E28B0;
}
#pragma peephole reset
#pragma scheduling reset
extern f32 lbl_803E28A0;
extern f32 lbl_803E28A4;
extern f32 lbl_803E28A8;
extern f32 lbl_803E28F4;
extern f32 lbl_803E290C;
extern f32 lbl_803E2910;
extern f32 lbl_803E2924;
extern f32 lbl_803E2928;
extern f32 lbl_803E292C;
extern f32 lbl_803E2930;

extern void fn_80293018(int idx, f32* outA, f32* outB);

#pragma scheduling off
#pragma peephole off
void fn_80152EC0(int obj, int state)
{
    f32 zero;
    f32 lblA;
    f32 a, b;

    zero = lbl_803E286C;
    ((BaddieState *)state)->unk2AC = zero;
    ((BaddieState *)state)->unk2E4 = 1;
    ((BaddieState *)state)->unk308 = lbl_803E28A0;
    ((BaddieState *)state)->unk300 = lbl_803E28A4;
    lblA = lbl_803E2894;
    ((BaddieState *)state)->unk304 = lblA;
    ((BaddieState *)state)->unk320 = 1;
    *(f32 *)&((BaddieState *)state)->eventFlags = lblA;
    ((BaddieState *)state)->unk321 = 3;
    ((BaddieState *)state)->unk318 = lblA;
    ((BaddieState *)state)->unk322 = 1;
    ((BaddieState *)state)->unk31C = lblA;
    *(f32*)(state + 0x324) = ((GameObject *)obj)->anim.localPosX;
    *(f32*)(state + 0x328) = ((GameObject *)obj)->anim.localPosY;
    *(f32*)(state + 0x32c) = ((GameObject *)obj)->anim.localPosZ;
    ((BaddieState *)state)->unk33A = 0;
    ((BaddieState *)state)->inWhirlpoolGroup = 0;
    *(s16*)(state + 0x338) = 0;
    *(f32*)(state + 0x330) = zero;
    *(f32*)(state + 0x334) = zero;
    ((BaddieState *)state)->pathStep = lbl_803E28A8;

    fn_80293018((s32)(u32)*(u16*)(state + 0x338), &a, &b);
    ((GameObject *)obj)->anim.localPosX = a * ((BaddieState *)state)->unk2A8 + *(f32*)(state + 0x324);
    ((GameObject *)obj)->anim.localPosZ = b * ((BaddieState *)state)->unk2A8 + *(f32*)(state + 0x32c);
}
#pragma peephole reset
#pragma scheduling reset

extern void Sfx_PlayFromObjectLimited(int obj, int sfx, int prio);
extern void fn_8014D08C(int obj, int p2, f32 mult, int a, int b, u8 c);
extern void fn_8015355C(int obj, int p2);
extern EffectInterface **gPartfxInterface;

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015355C(int obj, int p2)
{
    u8 count = 0;
    switch (((GameObject *)obj)->anim.currentMove) {
    case 1:
        count = 1;
        break;
    case 2:
        count = 1;
        break;
    case 3:
        count = 1;
        break;
    case 5:
        if ((((BaddieState *)p2)->controlFlags & 0x80000000) != 0) {
            count = 0xa;
        }
        break;
    case 7:
        break;
    }
    if (count != 0 && (((BaddieState *)p2)->controlFlags & 0x40000000) == 0) {
        u8 spawn = count;
        while (spawn != 0) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x802, NULL, 2, -1, NULL);
            spawn--;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void fn_80153BFC(int obj, int p2)
{
    ((BaddieState *)p2)->inWhirlpoolGroup = ((BaddieState *)p2)->inWhirlpoolGroup & 0xbf;
    if ((((BaddieState *)p2)->controlFlags & 0x40000000) != 0 && ((GameObject *)obj)->anim.currentMove != 1) {
        Sfx_PlayFromObjectLimited(obj, 0x49c, 2);
        ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, p2, 1, lbl_803E290C, 0, 0);
    }
    fn_8015355C(obj, p2);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80153C90(int unused, int p2)
{
    f32 ten;
    f32 oc;
    ((BaddieState *)p2)->unk2AC = lbl_803E2924;
    ((BaddieState *)p2)->unk2E4 = 1;
    ((BaddieState *)p2)->unk308 = lbl_803E28F4;
    ((BaddieState *)p2)->unk300 = lbl_803E2928;
    ((BaddieState *)p2)->unk304 = lbl_803E292C;
    ((BaddieState *)p2)->unk320 = 0;
    ten = lbl_803E2910;
    *(f32 *)&((BaddieState *)p2)->eventFlags = ten;
    ((BaddieState *)p2)->unk321 = 7;
    oc = lbl_803E290C;
    ((BaddieState *)p2)->unk318 = oc;
    ((BaddieState *)p2)->unk322 = 0;
    ((BaddieState *)p2)->unk31C = ten;
    ((BaddieState *)p2)->unk33A = 0;
    ((BaddieState *)p2)->inWhirlpoolGroup = 0;
    *(f32*)(p2 + 0x324) = lbl_803E2930;
    ((BaddieState *)p2)->pathStep = oc;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80152FA8(int obj, int p2, int unused, int msgFlag)
{
  if (((BaddieState *)p2)->inWhirlpoolGroup != 0) {
    if (msgFlag == 16) {
      ((BaddieState *)p2)->reactionFlags = ((BaddieState *)p2)->reactionFlags | 0x28;
      Sfx_PlayFromObject(obj, SFXfox_climbgrunt4);
      *(s16 *)&((BaddieState *)p2)->hitCounter = 0;
    }
  } else if (msgFlag != 17) {
    if (msgFlag == 16) {
      ((BaddieState *)p2)->reactionFlags = ((BaddieState *)p2)->reactionFlags | 0x20;
    } else {
      ((BaddieState *)p2)->reactionFlags = ((BaddieState *)p2)->reactionFlags | 0x8;
      Sfx_PlayFromObject(obj, SFXfox_climbgrunt4);
      *(s16 *)&((BaddieState *)p2)->hitCounter = 0;
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E28D4;
extern f32 lbl_803E28D8;
extern f32 lbl_803E28F0;
extern f32 lbl_803E2900;
extern f32 lbl_803E2904;
extern f32 lbl_803E2908;
extern f64 lbl_803E2918;
extern f64 lbl_803E2938;
extern f32 lbl_803E2940;
extern f32 lbl_803E2944;
extern f32 lbl_803E2948;
extern f32 lbl_803E2920;
extern f32 lbl_803E294C;
extern f32 lbl_803E2950;
extern f32 lbl_803E2954;
extern f32 lbl_803E2958;
extern u8 lbl_803DBCC0[8];
extern int lbl_803DBCC8;
extern uint countLeadingZeros(uint x);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int obj, int a, int b, int c, int d);
extern void voxmaps_worldToGrid(f32 *pos, int *grid);
extern int voxmaps_traceLine(int *a, int *b, int c, u8 *out, int e);
extern f32 PSVECMag(f32 *v);
extern s16 getAngle(f32 dx, f32 dz);

#pragma scheduling off
#pragma peephole off
void fn_80153248(int obj, int state)
{
    int *curve;
    f32 vec[3];
    f32 worldPos[3];
    int gridB[3];
    int gridA[3];
    u8 hitOut;
    int p29c;

    curve = *(int **)state;
    if (((BaddieState *)state)->inWhirlpoolGroup != 0) {
        ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x80;
    }
    if ((((BaddieState *)state)->controlFlags & 0x80000000) != 0) {
        Sfx_PlayFromObject(obj, SFXfox_climbgrunt3);
    }
    if ((((BaddieState *)state)->controlFlags & 0x2000) != 0) {
        if (Curve_AdvanceAlongPath(curve, lbl_803E28D4 * ((BaddieState *)state)->pathStep) != 0
            || ((RomCurveWalker *)curve)->unk10 != 0) {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0) {
                if ((*gRomCurveInterface)->initCurve(*(void **)state, (void *)obj, lbl_803E28B8,
                                                     &lbl_803DBCB8, -1) != 0) {
                    ((BaddieState *)state)->controlFlags = ((BaddieState *)state)->controlFlags & ~0x2000;
                }
            }
        }
    }
    ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
    p29c = *(int *)&((BaddieState *)state)->trackedObj;
    vec[0] = ((GameObject *)p29c)->anim.localPosX - ((GameObject *)obj)->anim.localPosX;
    vec[1] = (lbl_803E28D8 + ((GameObject *)p29c)->anim.localPosY) - ((GameObject *)obj)->anim.localPosY;
    vec[2] = ((GameObject *)p29c)->anim.localPosZ - ((GameObject *)obj)->anim.localPosZ;
    PSVECMag(vec);
    *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) + timeDelta;
    if (*(u32*)(state + 0x340) != 0 || *(f32*)(state + 0x32c) > lbl_803E28C8) {
        *(u32 *)&((BaddieState *)state)->unk2E4 = *(u32 *)&((BaddieState *)state)->unk2E4 | 0x10000;
        *(f32*)(state + 0x324) = lbl_803E28B0;
        *(f32*)(state + 0x32c) = lbl_803E28B0;
    } else {
        worldPos[0] = ((GameObject *)obj)->anim.localPosX;
        worldPos[1] = ((GameObject *)obj)->anim.localPosY;
        worldPos[2] = ((GameObject *)obj)->anim.localPosZ;
        voxmaps_worldToGrid(worldPos, gridA);
        worldPos[0] = ((RomCurveWalker *)curve)->unk68;
        worldPos[1] = ((RomCurveWalker *)curve)->unk6C;
        worldPos[2] = ((RomCurveWalker *)curve)->unk70;
        voxmaps_worldToGrid(worldPos, gridB);
        if (((countLeadingZeros(((BaddieState *)state)->controlFlags) >> 5) & 0x01000000) != 0) {
            if (voxmaps_traceLine(gridB, gridA, 0, &hitOut, 0) == 0) {
                *(u32 *)&((BaddieState *)state)->unk2E4 = *(u32 *)&((BaddieState *)state)->unk2E4 | 0x10000;
                *(f32*)(state + 0x324) = lbl_803E28B0;
                *(f32*)(state + 0x32c) = lbl_803E28B0;
            }
        }
    }
    fn_8014C678(obj, state, vec, lbl_803E28BC, lbl_803E28C0, lbl_803E28C4, 1);
    fn_8014CD1C(obj, state, 0xf, lbl_803E28CC, lbl_803E28D0, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_80153640(int obj, int state)
{
    u8 *fx;
    int newObj;
    u32 rnd;
    int p29c;

    if ((u8)Obj_IsLoadingLocked() != 0) {
        fx = (u8 *)Obj_AllocObjectSetup(0x24, 0x51b);
        ((GameObject *)fx)->anim.rootMotionScale = ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)fx)->anim.localPosX = lbl_803E28F0 + ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)fx)->anim.localPosY = ((GameObject *)obj)->anim.localPosZ;
        *(u8*)(fx + 0x4) = 1;
        *(u8*)(fx + 0x5) = 1;
        *(u8*)(fx + 0x6) = 0xff;
        *(u8*)(fx + 0x7) = 0xff;
        newObj = Obj_SetupObject((int)fx, 5, -1, -1, 0);
        if (newObj != 0) {
            p29c = *(int *)&((BaddieState *)state)->trackedObj;
            ((GameObject *)newObj)->anim.velocityX = lbl_803E28F4 * (((GameObject *)p29c)->anim.localPosX - ((GameObject *)fx)->anim.rootMotionScale);
            rnd = randomGetRange(-10, 10);
            p29c = *(int *)&((BaddieState *)state)->trackedObj;
            ((GameObject *)newObj)->anim.velocityY = lbl_803E28F4 *
                ((lbl_803E28F0 + ((GameObject *)p29c)->anim.localPosY + (f32)(s32)rnd) - ((GameObject *)fx)->anim.localPosX);
            p29c = *(int *)&((BaddieState *)state)->trackedObj;
            ((GameObject *)newObj)->anim.velocityZ = lbl_803E28F4 * (((GameObject *)p29c)->anim.localPosZ - ((GameObject *)fx)->anim.localPosY);
            *(int *)&((GameObject *)newObj)->unkC4 = obj;
        }
        Sfx_PlayFromObject(obj, 0x49a);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

#pragma scheduling off
#pragma peephole off
void fn_8015383C(int obj, int state)
{
    u32 hit;
    int losDetected;
    f32 worldPos[3];
    f32 vec[3];
    int gridB[2];
    int gridA[2];
    u8 hitOut;
    u8 flagByte;
    u32 rnd;
    s16 angle;

    ((BaddieState *)state)->inWhirlpoolGroup = ((BaddieState *)state)->inWhirlpoolGroup & 0x7f;
    losDetected = 0;
    {
        int p29c = *(int *)&((BaddieState *)state)->trackedObj;
        vec[0] = ((GameObject *)obj)->anim.localPosX - ((GameObject *)p29c)->anim.localPosX;
        vec[1] = ((GameObject *)obj)->anim.localPosY - ((GameObject *)p29c)->anim.localPosY;
        vec[2] = ((GameObject *)obj)->anim.localPosZ - ((GameObject *)p29c)->anim.localPosZ;
    }
    if (PSVECMag(vec) < lbl_803E2900
        && (*(u16*)(*(int *)&((BaddieState *)state)->trackedObj + 0xb0) & 0x1000) == 0) {
        worldPos[0] = ((GameObject *)obj)->anim.localPosX;
        worldPos[1] = lbl_803E2904 + ((GameObject *)obj)->anim.localPosY;
        worldPos[2] = ((GameObject *)obj)->anim.localPosZ;
        voxmaps_worldToGrid(worldPos, gridA);
        {
            int p29c = *(int *)&((BaddieState *)state)->trackedObj;
            worldPos[0] = ((GameObject *)p29c)->anim.localPosX;
            worldPos[1] = lbl_803E2908 + ((GameObject *)p29c)->anim.localPosY;
            worldPos[2] = ((GameObject *)p29c)->anim.localPosZ;
        }
        voxmaps_worldToGrid(worldPos, gridB);
        hit = (u8)voxmaps_traceLine(gridB, gridA, 0, &hitOut, 0);
        if (hit != 0) {
            int p29c = *(int *)&((BaddieState *)state)->trackedObj;
            fn_8014CF7C(obj, state, 0x14, 0, ((GameObject *)p29c)->anim.localPosX, ((GameObject *)p29c)->anim.localPosZ);
            angle = (s16)(getAngle(vec[0], vec[2]) - ((GameObject *)obj)->anim.rotX);
            if (angle > 0x8000) angle = angle + 1;
            if (angle < -0x8000) angle = angle - 1;
            if (angle < 0) angle = -angle;
            if (angle < 1000) losDetected = 1;
        }
    } else {
        hit = 0;
    }
    flagByte = ((BaddieState *)state)->inWhirlpoolGroup;
    if ((flagByte & 0x40) == 0) {
        Sfx_PlayFromObjectLimited(obj, 0x49b, 2);
        ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, state, 2, lbl_803E290C, 0, 0);
        ((BaddieState *)state)->inWhirlpoolGroup = (u8)((((BaddieState *)state)->inWhirlpoolGroup) | 0x40);
        ((BaddieState *)state)->unk33A = 0;
    } else if ((((BaddieState *)state)->controlFlags & 0x40000000) != 0) {
        u8 mode;
        if ((u8)hit != 0) {
            if (((BaddieState *)state)->unk33A != 0) {
                ((BaddieState *)state)->unk33A = ((BaddieState *)state)->unk33A - 1;
                mode = (u8)((GameObject *)obj)->anim.currentMove;
            } else if (((GameObject *)obj)->anim.currentMove != 5 && losDetected) {
                mode = 5;
                ((BaddieState *)state)->unk33A = lbl_803DBCC0[((BaddieState *)state)->inWhirlpoolGroup & 3];
                ((BaddieState *)state)->inWhirlpoolGroup = (u8)((*(s8 *)&((BaddieState *)state)->inWhirlpoolGroup + 1) & 0xc3);
            } else {
                mode = 4;
                rnd = randomGetRange(1, 2);
                ((BaddieState *)state)->unk33A = (u8)rnd;
            }
        } else {
            rnd = randomGetRange(2, 4);
            mode = (u8)rnd;
            if (mode == 2) {
                mode = 0;
            } else if (mode == 4) {
                Sfx_PlayFromObject(obj, 0x357);
            }
        }
        ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, state, mode, lbl_803E2910, 0, 0);
    }
    if (((GameObject *)obj)->anim.currentMove == 5) {
        f32 sct = ((GameObject *)obj)->anim.currentMoveProgress;
        if ((double)sct >= lbl_803E2918
            && (double)sct < lbl_803E2918 + ((BaddieState *)state)->unk308 * timeDelta) {
            fn_80153640(obj, state);
            fn_8015355C(obj, state);
            return;
        }
    }
    *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
    if (*(f32*)(state + 0x324) <= lbl_803E2920) {
        rnd = randomGetRange(0x96, 0x12c);
        *(f32*)(state + 0x324) = (f32)(s32)rnd;
        Sfx_PlayFromObject(obj, SFXwatery_bubble3);
    }
    fn_8015355C(obj, state);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80153CF8(int obj, int state, int p3, int msgFlag)
{
    int cond = 0;
    int kind = ((GameObject *)obj)->anim.currentMove;
    if (kind == 5) {
    } else if (kind == 4) {
    } else if (kind == 6) {
        if ((double)((GameObject *)obj)->anim.currentMoveProgress < lbl_803E2938) {
        } else {
            goto checkedKind;
        }
    } else {
        goto checkedKind;
    }

    if (msgFlag != 0xe) {
        cond = 1;
    }

checkedKind:
    if (msgFlag == 0x10) {
        if (cond != 0) {
            ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x20;
        }
    } else if (cond != 0) {
        if (((BaddieState *)state)->inWhirlpoolGroup == 0) {
            ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x8;
            *(s16 *)&((BaddieState *)state)->hitCounter = 0;
            Sfx_PlayFromObject(obj, SFXfox_healthgasp4);
        }
    } else if (msgFlag == 0x11) {
        *(f32*)(state + 0x32c) = lbl_803E2940;
        *(f32*)(state + 0x324) = lbl_803E2944;
        ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, state, 4, lbl_803E2948, 0, 3);
        *(u32 *)&((BaddieState *)state)->unk2E4 = *(u32 *)&((BaddieState *)state)->unk2E4 | 0x10000;
        ((BaddieState *)state)->inWhirlpoolGroup = 0x3c;
    } else {
        ((BaddieState *)state)->reactionFlags = ((BaddieState *)state)->reactionFlags | 0x10;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_80153E0C(int obj, int state)
{
    int *curve;
    u32 rnd;
    u8 ctr;

    curve = *(int **)state;
    ((BaddieState *)state)->unk33A = 0;
    *(f32*)(state + 0x328) = lbl_803E294C;
    if ((((BaddieState *)state)->controlFlags & 0x2000) != 0) {
        if (Curve_AdvanceAlongPath(curve, ((BaddieState *)state)->pathStep) != 0 || ((RomCurveWalker *)curve)->unk10 != 0) {
            if ((*gRomCurveInterface)->goNextPoint(curve) != 0) {
                if ((*gRomCurveInterface)->initCurve(*(void **)state, (void *)obj, lbl_803E2950,
                                                     &lbl_803DBCC8, -1) != 0) {
                    ((BaddieState *)state)->controlFlags = ((BaddieState *)state)->controlFlags & ~0x2000;
                }
            }
        }
        if (lbl_803E294C == *(f32*)(state + 0x32c)) {
            if (((GameObject *)obj)->anim.currentMove == 0) {
                fn_8014CF7C(obj, state, 0x3c, 0, ((RomCurveWalker *)curve)->unk68, ((RomCurveWalker *)curve)->unk70);
            }
            if (*(f32*)(state + 0x324) > lbl_803E294C) {
                *(f32*)(state + 0x324) = *(f32*)(state + 0x324) - timeDelta;
                if (*(f32*)(state + 0x324) <= lbl_803E294C) {
                    *(u32 *)&((BaddieState *)state)->unk2E4 = *(u32 *)&((BaddieState *)state)->unk2E4 & 0xfffeffff;
                    *(f32*)(state + 0x324) = lbl_803E294C;
                }
            }
        }
    }
    if (*(f32*)(state + 0x32c) > lbl_803E294C) {
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= lbl_803E294C) {
            ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, state, 6, lbl_803E2948, 0, 3);
            *(f32*)(state + 0x32c) = lbl_803E294C;
        } else if ((((BaddieState *)state)->controlFlags & 0x40000000) != 0) {
            ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, state, 5, lbl_803E2954, 0, 3);
        }
    } else if ((((BaddieState *)state)->controlFlags & 0x40000000) != 0) {
        ((void(*)(int, int, int, f32, int, int))fn_8014D08C)(obj, state, 0, lbl_803E2958, 0, 3);
    }
    ((GameObject *)obj)->anim.rotY = ((BaddieState *)state)->unk19C;
    ((GameObject *)obj)->anim.rotZ = ((BaddieState *)state)->unk19E;
    *(f32*)(state + 0x330) = *(f32*)(state + 0x330) - timeDelta;
    if (*(f32*)(state + 0x330) <= lbl_803E294C) {
        rnd = randomGetRange(0x3c, 0x78);
        *(f32*)(state + 0x330) = (f32)(s32)rnd;
        Sfx_PlayFromObject(obj, SFXfox_healthgasp3);
    }
    ctr = ((BaddieState *)state)->inWhirlpoolGroup;
    if (ctr != 0) {
        ((BaddieState *)state)->inWhirlpoolGroup = ctr - 1;
    }
}
#pragma peephole reset
#pragma scheduling reset
