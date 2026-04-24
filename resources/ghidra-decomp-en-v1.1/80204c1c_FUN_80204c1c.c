// Function: FUN_80204c1c
// Entry: 80204c1c
// Size: 524 bytes

void FUN_80204c1c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  byte bVar6;
  int iVar7;
  undefined8 extraout_f1;
  double dVar8;
  
  iVar1 = FUN_8028683c();
  iVar7 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_80020078(0xd5d);
  uVar4 = FUN_80020078(0xd59);
  uVar5 = FUN_80020078(0xd5a);
  if (((((uVar3 & 0xff) != 0) && (-1 < *(char *)(iVar7 + 7))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)(iVar7 + 7) >> 6 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)(iVar7 + 7) >> 5 & 1) == 0)))) {
    FUN_8000bb38(0,0x109);
  }
  *(byte *)(iVar7 + 7) = (byte)((uVar3 & 0xff) << 7) | *(byte *)(iVar7 + 7) & 0x7f;
  *(byte *)(iVar7 + 7) = (byte)((uVar4 & 0xff) << 6) & 0x40 | *(byte *)(iVar7 + 7) & 0xbf;
  *(byte *)(iVar7 + 7) = (byte)((uVar5 & 0xff) << 5) & 0x20 | *(byte *)(iVar7 + 7) & 0xdf;
  uVar3 = FUN_80020078(0x5e8);
  if (((uVar3 == 0) && (uVar3 = FUN_80020078(0x5ee), uVar3 != 0)) &&
     (uVar3 = FUN_80020078(0x5ef), uVar3 != 0)) {
    FUN_800201ac(0x5e8,1);
  }
  dVar8 = (double)*(float *)(iVar2 + 0x14);
  FUN_8005b128();
  bVar6 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (bVar6 == 2) {
    FUN_802046d0(extraout_f1,dVar8,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if ((bVar6 < 2) && (bVar6 != 0)) {
    if ((DAT_803dcde8 != 0) &&
       (DAT_803dcde8 = DAT_803dcde8 - (short)(int)FLOAT_803dc074, DAT_803dcde8 < 1)) {
      DAT_803dcde8 = 0;
    }
    FUN_80204958(extraout_f1,dVar8,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_801d84c4(iVar7 + 8,2,-1,-1,0xdce,(int *)0x95);
  FUN_801d8650(iVar7 + 8,4,-1,-1,0xdce,(int *)0x37);
  FUN_801d8650(iVar7 + 8,1,-1,-1,0xdce,(int *)0xe4);
  FUN_800201ac(0xdcf,0);
  FUN_80286888();
  return;
}

