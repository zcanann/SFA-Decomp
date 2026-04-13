// Function: FUN_8023a5a4
// Entry: 8023a5a4
// Size: 288 bytes

/* WARNING: Removing unreachable block (ram,0x8023a69c) */
/* WARNING: Removing unreachable block (ram,0x8023a694) */
/* WARNING: Removing unreachable block (ram,0x8023a5bc) */
/* WARNING: Removing unreachable block (ram,0x8023a5b4) */

void FUN_8023a5a4(void)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  ushort *puVar4;
  int local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  
  puVar1 = FUN_80037048(2,local_48);
  for (iVar3 = 0; iVar3 < local_48[0]; iVar3 = iVar3 + 1) {
    puVar4 = (ushort *)*puVar1;
    if ((**(short **)(puVar4 + 0x26) == 0x80d) || (**(short **)(puVar4 + 0x26) == 0x859)) {
      iVar2 = FUN_80021884();
      *puVar4 = (ushort)iVar2;
      iVar2 = FUN_80021884();
      puVar4[1] = -(short)iVar2;
      uStack_3c = DAT_803dd150 ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_8022ec10((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8130),puVar4)
      ;
    }
    puVar1 = puVar1 + 1;
  }
  return;
}

