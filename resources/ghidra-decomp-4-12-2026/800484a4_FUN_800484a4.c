// Function: FUN_800484a4
// Entry: 800484a4
// Size: 436 bytes

void FUN_800484a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined8 uVar6;
  char acStack_418 [1048];
  
  uVar6 = FUN_80286840();
  iVar4 = (int)uVar6;
  if ((param_11 == 0) && ((&DAT_8035fe68)[iVar4] == 0)) {
    uVar6 = FUN_8028fde8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)acStack_418,s__s_romlist_zlb_802cd0dc,
                         (&PTR_s_frontend_802cc518)[iVar4],param_12,param_13,param_14,param_15,
                         param_16);
    puVar1 = FUN_8002419c(DAT_803dd90c);
    iVar2 = FUN_80249300(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_418,
                         (int)puVar1);
    if (iVar2 != 0) {
      iVar2 = FUN_80023d8c(puVar1[0xd],0x7d7d7d7d);
      (&DAT_8035fe68)[iVar4] = iVar2;
      DAT_803dd8f4 = 1;
      FUN_80249610(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1,
                   (&DAT_8035fe68)[iVar4],puVar1[0xd],0,FUN_800426d0,2,param_15,param_16);
    }
  }
  else {
    if ((&DAT_8035fe68)[iVar4] == 0) {
      uVar5 = FUN_8028fde8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)acStack_418,s__s_romlist_zlb_802cd0dc,
                           (&PTR_s_frontend_802cc518)[iVar4],param_12,param_13,param_14,param_15,
                           param_16);
      piVar3 = FUN_8002419c(DAT_803dd90c);
      iVar2 = FUN_80249300(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_418
                           ,(int)piVar3);
      if (iVar2 == 0) goto LAB_80048640;
      iVar2 = FUN_80023d8c(piVar3[0xd],0x7d7d7d7d);
      (&DAT_8035fe68)[iVar4] = iVar2;
      FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar3,
                   (&DAT_8035fe68)[iVar4],piVar3[0xd],0,param_13,param_14,param_15,param_16);
      FUN_802493c8(piVar3);
      FUN_800241f8(DAT_803dd90c,piVar3);
    }
    piVar3 = (int *)(DAT_803600bc + (int)((ulonglong)uVar6 >> 0x20));
    if (*piVar3 == -0x5310113) {
      FUN_8004b7d4((&DAT_8035fe68)[iVar4] + 0x10,piVar3[3],param_11);
      FUN_80242114(param_11,piVar3[1]);
    }
  }
LAB_80048640:
  FUN_8028688c();
  return;
}

