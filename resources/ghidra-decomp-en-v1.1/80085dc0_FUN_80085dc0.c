// Function: FUN_80085dc0
// Entry: 80085dc0
// Size: 656 bytes

void FUN_80085dc0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int *param_11,int param_12,int *param_13,int param_14,
                 int *param_15,int param_16)

{
  short *psVar1;
  int iVar2;
  undefined2 *puVar3;
  int *piVar4;
  short *psVar5;
  int *piVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  float local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  uVar7 = FUN_8028683c();
  psVar1 = (short *)((ulonglong)uVar7 >> 0x20);
  piVar4 = (int *)uVar7;
  if (*(char *)((int)param_11 + 0x7b) != '\0') {
    DAT_803ddd88 = 1;
    DAT_803ddd80 = 0x5a;
    DAT_803ddd8c = 0x42;
  }
  *(undefined2 *)(param_11 + 0x16) = *(undefined2 *)((int)param_11 + 0x5e);
  *(undefined2 *)((int)param_11 + 0x5a) = 0xffc4;
  piVar6 = param_13;
  uVar7 = FUN_80086ac4(extraout_f1,param_2,param_3,psVar1,*piVar4,(int)param_11,0);
  FUN_80086404(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar1,*piVar4,param_11
               ,(int *)0x1,piVar6,param_14,param_15,param_16);
  psVar5 = (short *)**(undefined4 **)(psVar1 + 0x5c);
  if ((short *)**(undefined4 **)(psVar1 + 0x5c) == (short *)0x0) {
    psVar5 = psVar1;
  }
  *param_13 = *(int *)(*(int *)(psVar5 + 0x3e) + *(char *)((int)psVar5 + 0xad) * 4);
  *piVar4 = (int)psVar5;
  FUN_80084c74((int)psVar1,(int)param_11);
  if ((*(char *)((int)param_11 + 0x7a) == '\x01') &&
     (iVar2 = FUN_80065a20((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                           (double)*(float *)(psVar1 + 10),psVar1,local_28,0), iVar2 == 0)) {
    *(float *)(psVar1 + 8) =
         *(float *)(psVar1 + 8) +
         ((*(float *)(psVar1 + 8) - local_28[0]) - *(float *)(param_12 + 0xc));
  }
  *psVar1 = *psVar1 + *(short *)((int)param_11 + 0x1a);
  if (((short *)*piVar4 != psVar1) && (DAT_803ddd58 == '\0')) {
    FUN_8008504c(*piVar4,(int)psVar1,(int)param_11);
  }
  FUN_80087418(psVar1,(short *)*piVar4,(int)param_11);
  *(undefined *)((int)param_11 + 0x8d) = 0;
  *(undefined *)((int)param_11 + 0x8e) = 0;
  *(undefined *)((int)param_11 + 0x7e) = 1;
  *(undefined2 *)((int)param_11 + 0x5a) = *(undefined2 *)(param_11 + 0x16);
  if (DAT_803ddd5a != '\0') {
    FUN_80082d5c(psVar1,*piVar4,param_11);
  }
  uStack_1c = (int)*(short *)(param_11 + 0x16) ^ 0x80000000;
  local_20 = 0x43300000;
  (&DAT_8039acb8)[*(char *)((int)param_11 + 0x57)] =
       (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803dfc38);
  *(undefined2 *)(&DAT_8039a158 + *(char *)((int)param_11 + 0x57) * 2) =
       *(undefined2 *)(param_11 + 0x16);
  uVar7 = FUN_802473b4();
  *(undefined8 *)(&DAT_8039a4b0 + *(char *)((int)param_11 + 0x57) * 8) = uVar7;
  uVar7 = FUN_802473b4();
  *(undefined8 *)(&DAT_8039a208 + *(char *)((int)param_11 + 0x57) * 8) = uVar7;
  if (((*piVar4 != 0) && (FUN_8003ab38(*piVar4), *(short *)(*piVar4 + 0x44) == 1)) &&
     (puVar3 = (undefined2 *)FUN_800396d0((int)psVar1,1), puVar3 != (undefined2 *)0x0)) {
    *puVar3 = 0;
    puVar3[1] = 0;
    puVar3[2] = 0;
  }
  FUN_80286888();
  return;
}

