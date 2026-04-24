// Function: FUN_802bacc0
// Entry: 802bacc0
// Size: 552 bytes

/* WARNING: Removing unreachable block (ram,0x802bae18) */
/* WARNING: Removing unreachable block (ram,0x802bad1c) */

uint FUN_802bacc0(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  bVar1 = *(byte *)(iVar5 + 0xa8c);
  if (bVar1 == 3) {
    *(undefined *)(param_3 + 0x56) = 0;
    *(undefined *)(iVar5 + 0x27a) = 1;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar5,7);
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      *(undefined *)(param_3 + 0x56) = 0;
      if (*(short *)(param_1 + 0xb4) == -1) {
        uVar3 = 7;
      }
      else if ((*(byte *)(iVar5 + 0xa8d) == 4) || (3 < *(byte *)(iVar5 + 0xa8d))) {
        uVar3 = 7;
      }
      else {
        uVar3 = 6;
      }
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar5,uVar3);
    }
    else if (bVar1 == 0) {
      *(undefined *)(param_3 + 0x56) = 0;
      if (*(short *)(param_1 + 0xb4) == -1) {
        for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
          FUN_800200e8(0x17b,1);
          *(byte *)(iVar5 + 0xa8e) = *(byte *)(iVar5 + 0xa8e) | 0x20;
        }
      }
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar5,1);
    }
  }
  else if (bVar1 == 5) {
    *(undefined *)(param_3 + 0x56) = 0;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar5,2);
  }
  else if (bVar1 < 5) {
    *(undefined *)(param_3 + 0x56) = 0;
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,iVar5,7);
  }
  (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar5 + 4);
  fVar2 = FLOAT_803e8234;
  *(float *)(iVar5 + 0x294) = FLOAT_803e8234;
  *(float *)(iVar5 + 0x284) = fVar2;
  *(float *)(iVar5 + 0x280) = fVar2;
  *(float *)(param_1 + 0x24) = fVar2;
  *(float *)(param_1 + 0x28) = fVar2;
  *(float *)(param_1 + 0x2c) = fVar2;
  return (uint)(-(int)*(char *)(param_3 + 0x56) | (int)*(char *)(param_3 + 0x56)) >> 0x1f;
}

