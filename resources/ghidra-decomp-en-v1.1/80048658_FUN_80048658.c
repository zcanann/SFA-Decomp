// Function: FUN_80048658
// Entry: 80048658
// Size: 720 bytes

void FUN_80048658(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined4 *param_12,
                 int param_13,uint param_14,int param_15,undefined4 param_16)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  int aiStack_68 [26];
  
  uVar1 = FUN_80286830();
  iVar8 = -1;
  if ((DAT_803600c8 != 0) || (DAT_80360174 != 0)) {
    iVar5 = param_13;
    uVar6 = param_14;
    iVar7 = param_15;
    uVar9 = extraout_f1;
    FUN_80243e74();
    uVar2 = DAT_803dd900;
    FUN_80243e9c();
    if (((uVar1 & 0x80000000) == 0) || ((uVar2 & 0x2000) != 0)) {
      if (((uVar1 & 0x40000000) == 0) || ((uVar2 & 0x1000) != 0)) {
        if ((DAT_803600cc == 0) || (((uVar2 & 0x1000) != 0 || (DAT_803600c8 == 0)))) {
          if ((DAT_80360178 != 0) && (((uVar2 & 0x2000) == 0 && (DAT_80360174 != 0)))) {
            iVar8 = 0x4b;
          }
        }
        else {
          iVar8 = 0x20;
        }
      }
      else {
        iVar8 = 0x20;
      }
    }
    else {
      iVar8 = 0x4b;
    }
    iVar3 = (&DAT_80360048)[iVar8];
    if (iVar3 == 0) {
      FUN_80249300(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&PTR_s_AUDIO_tab_802cbecc)[iVar8],(int)aiStack_68);
      uVar2 = FUN_80023d8c(0x400,0x7f7f7fff);
      FUN_80015888(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_68,uVar2,
                   0x400,(uVar1 & 0xffffff) << 1,iVar5,uVar6,iVar7,param_16);
      FUN_802493c8(aiStack_68);
      FUN_80242114(uVar2,0x400);
      if ((param_15 == 1) && (param_14 != 0)) {
        iVar8 = uVar2 + *(int *)(param_14 + param_13 * 4) + 4;
        uVar4 = *(undefined4 *)(iVar8 + 4);
        *param_12 = *(undefined4 *)(iVar8 + 8);
        *param_11 = uVar4;
      }
      else if ((param_15 == 2) && (param_14 != 0)) {
        FUN_80003494(param_14,uVar2,(param_13 + 1) * 4);
      }
      else {
        uVar4 = *(undefined4 *)(uVar2 + 0xc);
        *param_11 = *(undefined4 *)(uVar2 + 8);
        iVar8 = FUN_80291d74(-0x7fc23ddc,uVar2,3);
        if (iVar8 == 0) {
          *param_12 = 0xffffffff;
        }
        else {
          *param_12 = uVar4;
        }
      }
      FUN_800238c4(uVar2);
    }
    else if ((param_15 == 1) && (param_14 != 0)) {
      iVar3 = iVar3 + (uVar1 & 0xffffff) * 2 + *(int *)(param_14 + param_13 * 4) + 4;
      uVar4 = *(undefined4 *)(iVar3 + 4);
      *param_12 = *(undefined4 *)(iVar3 + 8);
      *param_11 = uVar4;
    }
    else if ((param_15 == 2) && (param_14 != 0)) {
      FUN_80003494(param_14,iVar3 + (uVar1 & 0xffffff) * 2,(param_13 + 1) * 4);
    }
    else {
      iVar3 = iVar3 + (uVar1 & 0xffffff) * 2;
      uVar4 = *(undefined4 *)(iVar3 + 0xc);
      *param_11 = *(undefined4 *)(iVar3 + 8);
      iVar8 = FUN_80291d74(-0x7fc23ddc,iVar3,3);
      if (iVar8 == 0) {
        *param_12 = 0xffffffff;
      }
      else {
        *param_12 = uVar4;
      }
    }
  }
  FUN_8028687c();
  return;
}

