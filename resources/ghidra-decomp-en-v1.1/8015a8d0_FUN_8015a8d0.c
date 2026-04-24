// Function: FUN_8015a8d0
// Entry: 8015a8d0
// Size: 264 bytes

void FUN_8015a8d0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  *(float *)(param_10 + 0x2ac) = FLOAT_803e3914;
  *(undefined4 *)(param_10 + 0x2e4) = 0x405009;
  *(float *)(param_10 + 0x304) = FLOAT_803e3918;
  *(undefined *)(param_10 + 800) = 0;
  fVar1 = FLOAT_803e391c;
  *(float *)(param_10 + 0x314) = FLOAT_803e391c;
  *(undefined *)(param_10 + 0x321) = 0;
  *(float *)(param_10 + 0x318) = FLOAT_803e38d4;
  *(undefined *)(param_10 + 0x322) = 0;
  *(float *)(param_10 + 0x31c) = fVar1;
  *(float *)(param_10 + 0x2fc) = *(float *)(param_10 + 0x2fc) * FLOAT_803e3920;
  iVar2 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
  FUN_8014d504((double)*(float *)(&DAT_803207c0 + iVar2),param_2,param_3,param_4,param_5,param_6,
               param_7,param_8,param_9,param_10,(uint)(byte)(&DAT_803207c8)[iVar2],0,0,in_r8,in_r9,
               in_r10);
  *(float *)(param_10 + 0x328) = FLOAT_803e38f0;
  FUN_80035ec0(param_9,0xe,1,0xfff);
  uVar3 = FUN_80026dc0();
  *(undefined4 *)(param_10 + 0x36c) = uVar3;
  FUN_80026cfc((double)FLOAT_803e3924,(double)FLOAT_803e3928,(double)FLOAT_803e392c,
               *(int *)(param_10 + 0x36c));
  *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 0x100;
  *(code **)(param_9 + 0x108) = FUN_8014d584;
  return;
}

