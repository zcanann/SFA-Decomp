// Function: FUN_80188d6c
// Entry: 80188d6c
// Size: 436 bytes

/* WARNING: Removing unreachable block (ram,0x80188ef8) */
/* WARNING: Removing unreachable block (ram,0x80188d7c) */

void FUN_80188d6c(short *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  float *pfVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  float afStack_38 [4];
  undefined4 local_28;
  uint uStack_24;
  
  param_1[2] = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x19) << 8;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  uVar2 = (uint)*(byte *)(param_2 + 0x1b);
  if (uVar2 != 0) {
    local_28 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4828) / FLOAT_803e4820;
    if (*(float *)(param_1 + 4) == FLOAT_803e4814) {
      *(float *)(param_1 + 4) = FLOAT_803e4810;
    }
    *(float *)(param_1 + 4) = *(float *)(param_1 + 4) * *(float *)(*(int *)(param_1 + 0x28) + 4);
    uStack_24 = uVar2;
  }
  sVar1 = param_1[0x23];
  if (((sVar1 == 0x7a1) || (sVar1 == 0x7a2)) || (sVar1 == 0x7a3)) {
    pfVar3 = *(float **)(param_1 + 0x5c);
    iVar4 = *(int *)**(undefined4 **)(param_1 + 0x3e);
    FUN_80026ec4(iVar4,0,pfVar3);
    FUN_80026ec4(iVar4,0,pfVar3 + 3);
    for (iVar5 = 1; iVar5 < (int)(uint)*(ushort *)(iVar4 + 0xe4); iVar5 = iVar5 + 1) {
      FUN_80026ec4(iVar4,iVar5,afStack_38);
      FUN_80188cf0(afStack_38,pfVar3,pfVar3 + 3);
    }
    FUN_80247edc((double)*(float *)(param_1 + 4),pfVar3,pfVar3);
    FUN_80247edc((double)*(float *)(param_1 + 4),pfVar3 + 3,pfVar3 + 3);
    dVar6 = FUN_80247f54(pfVar3 + 3);
    dVar7 = FUN_80247f54(pfVar3);
    if (dVar7 <= dVar6) {
      dVar6 = FUN_80247f54(pfVar3 + 3);
    }
    else {
      dVar6 = FUN_80247f54(pfVar3);
    }
    pfVar3[6] = (float)dVar6;
  }
  return;
}

