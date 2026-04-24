#include "ghidra_import.h"
#include "main/dll/WC/WCpushblock.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_8000bb38();
extern uint FUN_80020078();
extern undefined4 FUN_80021b8c();
extern uint FUN_80023d8c();
extern undefined4 FUN_8002a8e0();
extern void* FUN_8002becc();
extern undefined4 FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_800372f8();
extern undefined8 FUN_80038524();
extern undefined4 FUN_80054484();
extern undefined4 FUN_80054ed0();
extern undefined4 FUN_800e7f08();
extern undefined4 FUN_801eba58();
extern undefined4 FUN_801ecf60();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4 DAT_80329120;
extern undefined4 DAT_80329150;
extern undefined4 DAT_80329160;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd728;
extern undefined4 DAT_803de8e0;
extern undefined4 DAT_803e6778;
extern f32 FLOAT_803dcd20;
extern f32 FLOAT_803dcd28;
extern f32 FLOAT_803dcd2c;
extern f32 FLOAT_803e6780;
extern f32 FLOAT_803e6784;
extern f32 FLOAT_803e6788;
extern f32 FLOAT_803e67ac;
extern f32 FLOAT_803e67b4;
extern f32 FLOAT_803e67e0;
extern f32 FLOAT_803e680c;
extern f32 FLOAT_803e6828;
extern f32 FLOAT_803e682c;
extern f32 FLOAT_803e6830;
extern f32 FLOAT_803e685c;
extern f32 FLOAT_803e68e0;
extern f32 FLOAT_803e68e8;
extern f32 FLOAT_803e68ec;
extern f32 FLOAT_803e68f0;
extern f32 FLOAT_803e68f4;
extern f32 FLOAT_803e68f8;
extern f32 FLOAT_803e68fc;
extern f32 FLOAT_803e6900;
extern f32 FLOAT_803e6908;
extern f32 FLOAT_803e690c;
extern f32 FLOAT_803e6910;
extern f32 FLOAT_803e6914;
extern f32 FLOAT_803e6918;

/*
 * --INFO--
 *
 * Function: FUN_801ee104
 * EN v1.0 Address: 0x801EE0C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801EE104
 * EN v1.1 Size: 1364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ee104(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801ee658
 * EN v1.0 Address: 0x801EE0C4
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801EE658
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ee658(void)
{
  if (DAT_803de8e0 != 0) {
    FUN_80054484();
    DAT_803de8e0 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ee68c
 * EN v1.0 Address: 0x801EE0F8
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x801EE68C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ee68c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  if (DAT_803de8e0 == 0) {
    DAT_803de8e0 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0x186,param_10,param_11,param_12,param_13,param_14,param_15,param_16
                               );
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ee6f8
 * EN v1.0 Address: 0x801EE198
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x801EE6F8
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ee6f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar4;
  float local_38;
  float local_34;
  float local_30;
  ushort local_2c;
  ushort local_2a;
  ushort local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    FUN_8000bb38(0,0x127);
    local_20 = FLOAT_803e6908;
    local_1c = FLOAT_803e6908;
    local_18 = FLOAT_803e6908;
    local_24 = FLOAT_803e690c;
    local_2c = *param_9;
    local_2a = param_9[1];
    local_28 = param_9[2];
    local_38 = FLOAT_803e6908;
    local_34 = FLOAT_803e6910;
    local_30 = FLOAT_803e6914;
    FUN_80021b8c(&local_2c,&local_38);
    puVar2 = FUN_8002becc(0x18,0x119);
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    *(undefined *)(puVar2 + 2) = 2;
    *(undefined *)((int)puVar2 + 5) = 1;
    uVar3 = 0;
    uVar4 = FUN_80038524(param_9,4,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                         (float *)(puVar2 + 8),0);
    puVar2 = (undefined2 *)
             FUN_8002e088(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,
                          0xff,0xffffffff,(uint *)0x0,uVar3,in_r9,in_r10);
    if (puVar2 != (undefined2 *)0x0) {
      local_20 = FLOAT_803e6908;
      local_1c = FLOAT_803e6908;
      local_18 = FLOAT_803e6908;
      local_24 = FLOAT_803e690c;
      local_2c = *param_9;
      local_2a = param_9[1];
      local_28 = 0;
      local_38 = FLOAT_803e6908;
      local_34 = FLOAT_803e6908;
      local_30 = FLOAT_803e6918;
      FUN_80021b8c(&local_2c,&local_38);
      *(float *)(puVar2 + 0x12) = local_38;
      *(float *)(puVar2 + 0x14) = local_34;
      *(float *)(puVar2 + 0x16) = local_30;
      *(undefined4 *)(puVar2 + 0x7a) = 0x5a;
      *(ushort **)(puVar2 + 0x7c) = param_9;
      puVar2[2] = 0;
      puVar2[1] = 0;
      *puVar2 = 0;
    }
  }
  return;
}
