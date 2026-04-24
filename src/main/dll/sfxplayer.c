#include "ghidra_import.h"
#include "main/dll/sfxplayer.h"

extern void* FUN_8002becc();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803add98;
extern undefined4 DAT_803add9c;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803e70e8;
extern undefined4 DAT_803e70ec;
extern f32 FLOAT_803e7110;

/*
 * --INFO--
 *
 * Function: FUN_80207f80
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80207F80
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80207f80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  undefined2 *puVar2;
  char cVar5;
  undefined4 uVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 uVar7;
  undefined4 local_28;
  undefined4 local_24;
  
  uVar7 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar7 >> 0x20);
  local_28 = DAT_803e70e8;
  local_24 = DAT_803e70ec;
  uVar6 = extraout_f1;
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    uVar1 = (uint)uVar7 & 0xff;
    if ((&DAT_803add98)[uVar1 * 2] == 0) {
      puVar2 = FUN_8002becc(0x2c,0x6e8);
      *(undefined *)(puVar2 + 3) = 0xff;
      *(undefined *)((int)puVar2 + 7) = 0xff;
      *(undefined *)(puVar2 + 2) = 2;
      *(undefined *)((int)puVar2 + 5) = 1;
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x14);
      puVar2[0x12] = 0xffff;
      *(undefined *)(puVar2 + 0xd) = 0;
      *(undefined *)(puVar2 + 0xc) = 0;
      *(undefined *)((int)puVar2 + 0x19) = 0;
      cVar5 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar4 + 0xac));
      if (cVar5 == '\x02') {
        *(char *)((int)puVar2 + 0x1b) = (char)*(undefined2 *)((int)&local_28 + uVar1 * 2);
      }
      else {
        *(char *)((int)puVar2 + 0x1b) = (char)local_24;
      }
      *(undefined *)(puVar2 + 0xe) = 0;
      *(undefined *)((int)puVar2 + 0x1d) = 0;
      *(undefined *)(puVar2 + 0x13) = 100;
      *(undefined *)((int)puVar2 + 0x27) = 0;
      *(undefined *)(puVar2 + 0x14) = 0;
      *(float *)(puVar2 + 0x10) = FLOAT_803e7110;
      *(undefined *)((int)puVar2 + 0x29) = 0xd2;
      *(undefined *)(puVar2 + 0x15) = 0;
      uVar3 = FUN_8002e088(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           puVar2,5,*(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30)
                           ,in_r8,in_r9,in_r10);
      (&DAT_803add98)[uVar1 * 2] = uVar3;
      uVar6 = extraout_f1_01;
    }
    if ((&DAT_803add9c)[uVar1 * 2] == 0) {
      puVar2 = FUN_8002becc(4,0x71c);
      *(undefined *)(puVar2 + 3) = 0xff;
      *(undefined *)((int)puVar2 + 7) = 0xff;
      *(undefined *)(puVar2 + 2) = 2;
      *(undefined *)((int)puVar2 + 5) = 1;
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0xc);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x14);
      iVar4 = FUN_8002e088(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                           *(undefined *)(iVar4 + 0xac),0xffffffff,*(uint **)(iVar4 + 0x30),in_r8,
                           in_r9,in_r10);
      (&DAT_803add9c)[uVar1 * 2] = iVar4;
    }
  }
  FUN_8028688c();
  return;
}
