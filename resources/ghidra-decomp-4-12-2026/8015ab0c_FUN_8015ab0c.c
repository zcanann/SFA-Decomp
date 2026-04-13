// Function: FUN_8015ab0c
// Entry: 8015ab0c
// Size: 284 bytes

void FUN_8015ab0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int in_r6;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined *puVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  puVar4 = (&PTR_DAT_8032099c)[(uint)*(ushort *)(iVar3 + 0x338) * 2];
  if (in_r6 != 0x11) {
    if (in_r6 == 0x10) {
      *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 0x20;
    }
    else {
      if (*(ushort *)(iVar3 + 0x2a0) < 4) {
        FUN_8014d504((double)FLOAT_803e3950,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar1,iVar3,5,0,0,in_r8,in_r9,in_r10);
      }
      else {
        FUN_8014d504((double)FLOAT_803e3950,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     uVar1,iVar3,6,0,0,in_r8,in_r9,in_r10);
      }
      uVar2 = FUN_80022264(0,3);
      *(undefined *)(iVar3 + 0x33a) = puVar4[uVar2];
      *(uint *)(iVar3 + 0x2e8) = *(uint *)(iVar3 + 0x2e8) | 8;
      if ((int)(uint)*(ushort *)(iVar3 + 0x2b0) < in_r8) {
        *(undefined2 *)(iVar3 + 0x2b0) = 0;
      }
      else {
        *(ushort *)(iVar3 + 0x2b0) = *(ushort *)(iVar3 + 0x2b0) - (short)in_r8;
      }
      if (*(short *)(iVar3 + 0x2b0) == 0) {
        FUN_8000bb38(uVar1,0x49e);
      }
      if (in_r6 != 0x1a) {
        FUN_8000bb38(uVar1,0x22);
      }
    }
  }
  FUN_8028688c();
  return;
}

