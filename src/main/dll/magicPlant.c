#include "ghidra_import.h"
#include "main/dll/magicPlant.h"

extern undefined4 FUN_800067e8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d0();
extern int FUN_80006a10();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a5c();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_80035fe8();
extern undefined4 FUN_8014ccb8();
extern undefined4 FUN_8014d164();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern double FUN_80247f54();
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
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e34ac;
extern f32 FLOAT_803e34b8;
extern f32 FLOAT_803e34e8;
extern f32 FLOAT_803e34ec;
extern f32 FLOAT_803e34f0;
extern f32 FLOAT_803e34f4;
extern f32 FLOAT_803e34f8;
extern f32 FLOAT_803e3500;
extern f32 FLOAT_803e3504;
extern f32 FLOAT_803e3510;
extern f32 FLOAT_803e3514;
extern f32 FLOAT_803e3518;
extern f32 FLOAT_803e351c;
extern f32 FLOAT_803e3520;
extern f32 FLOAT_803e3524;
extern f32 FLOAT_803e3528;
extern f32 FLOAT_803e352c;
extern f32 FLOAT_803e3538;
extern f32 FLOAT_803e353c;
extern f32 FLOAT_803e3540;
extern f32 FLOAT_803e3548;
extern f32 FLOAT_803e354c;
extern f32 FLOAT_803e3550;
extern f32 FLOAT_803e3554;
extern f32 FLOAT_803e3558;
extern f32 FLOAT_803e355c;
extern f32 FLOAT_803e3560;
extern f32 FLOAT_803e3564;
extern f32 FLOAT_803e3568;
extern f32 FLOAT_803e356c;
extern f32 FLOAT_803e3570;
extern f32 FLOAT_803e3574;
extern f32 FLOAT_803e3578;
extern f32 FLOAT_803e357c;
extern f32 FLOAT_803e3580;
extern f32 FLOAT_803e3588;
extern f32 FLOAT_803e358c;
extern f32 FLOAT_803e3598;
extern f32 FLOAT_803e359c;
extern f32 FLOAT_803e35a0;
extern f32 FLOAT_803e35a4;
extern f32 FLOAT_803e35a8;
extern f32 FLOAT_803e35b8;

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
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e34e8;
  *(undefined4 *)(param_2 + 0x2e4) = 0x29;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x7000;
  *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x20000;
  *(float *)(param_2 + 0x308) = FLOAT_803e34ec;
  *(float *)(param_2 + 0x300) = FLOAT_803e34f0;
  *(float *)(param_2 + 0x304) = FLOAT_803e34f4;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e34b8;
  *(float *)(param_2 + 0x314) = FLOAT_803e34b8;
  *(undefined *)(param_2 + 0x321) = 0;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(float *)(param_2 + 0x32c) = FLOAT_803e34ac;
  *(float *)(param_1 + 0xa8) = FLOAT_803e34f8;
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
    FUN_80006824(param_1,0x248);
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
  
  dVar8 = (double)FLOAT_803e3514;
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x338));
  iVar4 = (int)(dVar8 * (double)FLOAT_803dc074 + (double)(float)(local_30 - DOUBLE_803e3530));
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
    if (dVar8 <= (double)(FLOAT_803e3518 * *(float *)(param_2 + 0x2a8))) {
      *(undefined *)(param_2 + 0x33a) = 1;
      *(undefined *)(param_2 + 0x33b) = 0;
    }
  }
  else if (*(char *)(param_2 + 0x33a) == '\x01') {
    dVar7 = (double)FLOAT_803dc074;
    dVar9 = -(double)(float)((double)FLOAT_803e351c * dVar7 - (double)*(float *)(param_1 + 8));
    if ((double)(*(float *)(param_2 + 0x328) - FLOAT_803e3520) < dVar9) {
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
          dVar6 = (double)FLOAT_803e3510;
          *(float *)(puVar3 + 6) = (float)(dVar6 + (double)*(float *)(param_1 + 8));
          *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_1 + 10);
          *(undefined *)(puVar3 + 2) = 1;
          *(undefined *)((int)puVar3 + 5) = 1;
          *(undefined *)(puVar3 + 3) = 0xff;
          *(undefined *)((int)puVar3 + 7) = 0xff;
          iVar4 = FUN_80017a5c(dVar6,dVar7,dVar8,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1,puVar3);
          if (iVar4 != 0) {
            *(ushort **)(iVar4 + 0xc4) = param_1;
            FUN_80006824((uint)param_1,0x249);
          }
        }
      }
    }
    else {
      *(undefined *)(param_2 + 0x33a) = 2;
    }
  }
  else {
    dVar9 = (double)(FLOAT_803e3524 * FLOAT_803dc074 + *(float *)(param_1 + 8));
    if ((double)*(float *)(param_2 + 0x328) <= dVar9) {
      *(undefined *)(param_2 + 0x33a) = 0;
    }
  }
  *(float *)(param_1 + 0x12) = FLOAT_803dc078 * (local_34 - *(float *)(param_1 + 6));
  *(float *)(param_1 + 0x14) = FLOAT_803dc078 * (float)(dVar9 - (double)*(float *)(param_1 + 8));
  *(float *)(param_1 + 0x16) = FLOAT_803dc078 * (local_38 - *(float *)(param_1 + 10));
  FUN_8014d164((double)FLOAT_803e3528,(double)FLOAT_803e352c,param_1,param_2,0xf,'\0');
  *(float *)(param_2 + 0x334) = *(float *)(param_2 + 0x334) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x334) <= FLOAT_803e3500) {
    uVar5 = FUN_80017760(0x3c,0x78);
    local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(param_2 + 0x334) = (float)(local_28 - DOUBLE_803e3508);
    FUN_80006824((uint)param_1,0x31);
  }
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x330) <= FLOAT_803e3500) {
    *(float *)(param_2 + 0x330) = FLOAT_803e3504;
    FUN_80006824((uint)param_1,0x24a);
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
  
  fVar1 = FLOAT_803e3504;
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3504;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = FLOAT_803e3538;
  *(float *)(param_2 + 0x300) = FLOAT_803e353c;
  fVar2 = FLOAT_803e352c;
  *(float *)(param_2 + 0x304) = FLOAT_803e352c;
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
  *(float *)(param_2 + 0x2fc) = FLOAT_803e3540;
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
        FUN_80006824(param_1,0x25b);
        *(undefined2 *)(param_2 + 0x2b0) = 0;
      }
    }
  }
  else if (param_4 == 0x10) {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x28;
    FUN_80006824(param_1,0x25b);
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
                          ((double)FLOAT_803e3550,*param_2,param_1,&DAT_803dc920,0xffffffff),
       cVar2 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    FUN_8014d3d0((short *)param_1,param_2,0xf,0);
    local_28 = pfVar3[0x1a] - *(float *)(param_1 + 6);
    local_24 = pfVar3[0x1b] - *(float *)(param_1 + 8);
    local_20 = pfVar3[0x1c] - *(float *)(param_1 + 10);
    FUN_8014ccb8((double)FLOAT_803e3554,(double)FLOAT_803e3558,(double)FLOAT_803e355c,(int)param_1,
                 (int)param_2,&local_28,'\x01');
    param_2[0xc9] = (float)param_2[0xc9] + FLOAT_803dc074;
    if (FLOAT_803e3560 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = FLOAT_803e3548;
    }
  }
  FUN_8014d164((double)FLOAT_803e3564,(double)FLOAT_803e3568,param_1,(int)param_2,0xf,'\0');
  param_2[0xca] = (float)param_2[0xca] - FLOAT_803dc074;
  if ((float)param_2[0xca] <= FLOAT_803e3548) {
    param_2[0xca] = FLOAT_803e354c;
    FUN_80006824((uint)param_1,0x25c);
  }
  param_2[0xcb] = FLOAT_803e3548;
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
    FUN_80006824((uint)param_9,0x25a);
  }
  if ((((param_10[0xb7] & 0x2000) != 0) &&
      (((iVar3 = FUN_80006a10((double)(FLOAT_803e356c * (float)param_10[0xbf]),pfVar5), iVar3 != 0
        || (pfVar5[4] != 0.0)) &&
       (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar4 != '\0')))) &&
     (cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3550,*param_10,param_9,&DAT_803dc920,0xffffffff),
     cVar4 != '\0')) {
    param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
  }
  FUN_80035fe8((int)param_9,0xe,1,0);
  iVar3 = param_10[0xa7];
  local_28 = *(float *)(iVar3 + 0xc) - *(float *)(param_9 + 6);
  local_24 = (FLOAT_803e3570 + *(float *)(iVar3 + 0x10)) - *(float *)(param_9 + 8);
  local_20 = *(float *)(iVar3 + 0x14) - *(float *)(param_9 + 10);
  FUN_80247f54(&local_28);
  param_10[0xcb] = (float)param_10[0xcb] + FLOAT_803dc074;
  if ((param_10[0xd0] != 0) || (FLOAT_803e3560 < (float)param_10[0xcb])) {
    param_10[0xb9] = param_10[0xb9] | 0x10000;
    fVar1 = FLOAT_803e3548;
    param_10[0xc9] = FLOAT_803e3548;
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
      fVar1 = FLOAT_803e3548;
      param_10[0xc9] = FLOAT_803e3548;
      param_10[0xcb] = fVar1;
    }
  }
  FUN_8014ccb8((double)FLOAT_803e3554,(double)FLOAT_803e3558,(double)FLOAT_803e355c,(int)param_9,
               (int)param_10,&local_28,'\x01');
  FUN_8014d164((double)FLOAT_803e3564,(double)FLOAT_803e3568,param_9,(int)param_10,0xf,'\0');
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
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3574;
  *(undefined4 *)(param_2 + 0x2e4) = 0x1009;
  *(float *)(param_2 + 0x308) = FLOAT_803e3578;
  *(float *)(param_2 + 0x300) = FLOAT_803e357c;
  *(float *)(param_2 + 0x304) = FLOAT_803e3580;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e3554;
  *(float *)(param_2 + 0x314) = FLOAT_803e3554;
  *(undefined *)(param_2 + 0x321) = 1;
  fVar2 = FLOAT_803e3568;
  *(float *)(param_2 + 0x318) = FLOAT_803e3568;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = FLOAT_803e3548;
  *(float *)(param_2 + 0x324) = FLOAT_803e3548;
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
    dVar5 = (double)FLOAT_803e3588;
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
           FLOAT_803e358c * (*(float *)(*(int *)(param_10 + 0x29c) + 0xc) - *(float *)(puVar3 + 4));
      uVar2 = FUN_80017760(0xfffffff6,10);
      fVar1 = FLOAT_803e358c;
      *(float *)(iVar4 + 0x28) =
           FLOAT_803e358c *
           ((FLOAT_803e3588 + *(float *)(*(int *)(param_10 + 0x29c) + 0x10) +
            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3590)) -
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
        FUN_80006824(param_1,0x246);
        *(undefined2 *)(param_2 + 0x2b0) = 0;
      }
      else {
        FUN_80006824(param_1,0x247);
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
  dVar7 = FUN_80247f54(&local_34);
  if (((double)FLOAT_803e3598 <= dVar7) ||
     ((*(ushort *)(*(int *)(param_10 + 0x29c) + 0xb0) & 0x1000) != 0)) {
    cVar5 = '\0';
  }
  else {
    local_28 = *(float *)(param_9 + 6);
    local_24 = FLOAT_803e359c + *(float *)(param_9 + 8);
    local_20 = *(undefined4 *)(param_9 + 10);
    FUN_80006a68(&local_28,asStack_44);
    iVar3 = *(int *)(param_10 + 0x29c);
    local_28 = *(float *)(iVar3 + 0xc);
    local_24 = FLOAT_803e35a0 + *(float *)(iVar3 + 0x10);
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
    FUN_8014d4c8((double)FLOAT_803e35a4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
    *(byte *)(param_10 + 0x33b) = *(byte *)(param_10 + 0x33b) | 0x40;
    *(undefined *)(param_10 + 0x33a) = 0;
  }
  else if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (cVar5 == '\0') {
      uVar6 = FUN_80017760(2,4);
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
        uVar4 = FUN_80017760(1,2);
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
    FUN_8014d4c8((double)FLOAT_803e35a8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)param_9,param_10,uVar6,0,0,in_r8,in_r9,in_r10);
  }
  if (param_9[0x50] == 5) {
    dVar7 = (double)*(float *)(param_9 + 0x4c);
    if ((DOUBLE_803e35b0 <= dVar7) &&
       (dVar7 < DOUBLE_803e35b0 +
                (double)(float)((double)*(float *)(param_10 + 0x308) * (double)FLOAT_803dc074))) {
      FUN_80153be0((double)*(float *)(param_10 + 0x308),DOUBLE_803e35b0,dVar7,param_4,param_5,
                   param_6,param_7,param_8,(uint)param_9,param_10);
      goto LAB_8015407c;
    }
  }
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - FLOAT_803dc074;
  if (*(float *)(param_10 + 0x324) <= FLOAT_803e35b8) {
    uStack_14 = FUN_80017760(0x96,300);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_10 + 0x324) = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e3590)
    ;
    FUN_80006824((uint)param_9,0x245);
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
    FUN_8014d4c8((double)FLOAT_803e35a4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
  }
  FUN_80153b00(param_9,param_10);
  return;
}
