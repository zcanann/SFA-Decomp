// Function: FUN_80085b34
// Entry: 80085b34
// Size: 656 bytes

void FUN_80085b34(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 *param_5)

{
  short *psVar1;
  int iVar2;
  undefined2 *puVar3;
  short **ppsVar4;
  short *psVar5;
  undefined8 uVar6;
  float local_28 [2];
  undefined4 local_20;
  uint uStack28;
  
  uVar6 = FUN_802860d8();
  psVar1 = (short *)((ulonglong)uVar6 >> 0x20);
  ppsVar4 = (short **)uVar6;
  if (*(char *)(param_3 + 0x7b) != '\0') {
    DAT_803dd108 = 1;
    DAT_803dd100 = 0x5a;
    DAT_803dd10c = 0x42;
  }
  *(undefined2 *)(param_3 + 0x58) = *(undefined2 *)(param_3 + 0x5e);
  *(undefined2 *)(param_3 + 0x5a) = 0xffc4;
  FUN_80086838(psVar1,*ppsVar4,param_3,0);
  FUN_80086178(psVar1,*ppsVar4,param_3,1);
  psVar5 = **(short ***)(psVar1 + 0x5c);
  if (**(short ***)(psVar1 + 0x5c) == (short *)0x0) {
    psVar5 = psVar1;
  }
  *param_5 = *(undefined4 *)(*(int *)(psVar5 + 0x3e) + *(char *)((int)psVar5 + 0xad) * 4);
  *ppsVar4 = psVar5;
  FUN_800849e8(psVar1,param_3);
  if ((*(char *)(param_3 + 0x7a) == '\x01') &&
     (iVar2 = FUN_800658a4((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                           (double)*(float *)(psVar1 + 10),psVar1,local_28,0), iVar2 == 0)) {
    *(float *)(psVar1 + 8) =
         *(float *)(psVar1 + 8) +
         ((*(float *)(psVar1 + 8) - local_28[0]) - *(float *)(param_4 + 0xc));
  }
  *psVar1 = *psVar1 + *(short *)(param_3 + 0x1a);
  if ((*ppsVar4 != psVar1) && (DAT_803dd0d8 == '\0')) {
    FUN_80084dc0(*ppsVar4,psVar1,param_3,(&DAT_8039a564)[*(char *)(param_3 + 0x57)]);
  }
  FUN_8008718c(psVar1,*ppsVar4,param_3);
  *(undefined *)(param_3 + 0x8d) = 0;
  *(undefined *)(param_3 + 0x8e) = 0;
  *(undefined *)(param_3 + 0x7e) = 1;
  *(undefined2 *)(param_3 + 0x5a) = *(undefined2 *)(param_3 + 0x58);
  if (DAT_803dd0da != '\0') {
    FUN_80082ad0(psVar1,*ppsVar4,param_3);
  }
  uStack28 = (int)*(short *)(param_3 + 0x58) ^ 0x80000000;
  local_20 = 0x43300000;
  (&DAT_8039a058)[*(char *)(param_3 + 0x57)] =
       (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803defb8);
  *(undefined2 *)(&DAT_803994f8 + *(char *)(param_3 + 0x57) * 2) = *(undefined2 *)(param_3 + 0x58);
  uVar6 = FUN_80246c50();
  iVar2 = *(char *)(param_3 + 0x57) * 8;
  *(int *)(&DAT_80399854 + iVar2) = (int)uVar6;
  *(int *)(&DAT_80399850 + iVar2) = (int)((ulonglong)uVar6 >> 0x20);
  uVar6 = FUN_80246c50();
  iVar2 = *(char *)(param_3 + 0x57) * 8;
  *(int *)(&DAT_803995ac + iVar2) = (int)uVar6;
  *(int *)(&DAT_803995a8 + iVar2) = (int)((ulonglong)uVar6 >> 0x20);
  if (*ppsVar4 != (short *)0x0) {
    FUN_8003aa40();
    if (((*ppsVar4)[0x22] == 1) &&
       (puVar3 = (undefined2 *)FUN_800395d8(psVar1,1), puVar3 != (undefined2 *)0x0)) {
      *puVar3 = 0;
      puVar3[1] = 0;
      puVar3[2] = 0;
    }
  }
  FUN_80286124();
  return;
}

