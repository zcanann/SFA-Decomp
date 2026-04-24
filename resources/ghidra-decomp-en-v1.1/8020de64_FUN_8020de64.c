// Function: FUN_8020de64
// Entry: 8020de64
// Size: 496 bytes

void FUN_8020de64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  ushort uVar4;
  char *pcVar5;
  byte *pbVar6;
  uint *puVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  undefined8 uVar11;
  
  iVar2 = FUN_80286834();
  iVar10 = *(int *)(iVar2 + 0xb8);
  DAT_803de984 = 0;
  FUN_800201ac(0xa63,1);
  uVar9 = 0;
  iVar8 = 0;
  puVar7 = &DAT_8032ae0c;
  pcVar5 = &DAT_803dce20;
  do {
    uVar3 = FUN_80020078(*puVar7);
    if (uVar3 != 0) {
      bVar1 = true;
      if ((*pcVar5 != '\0') && (uVar4 = FUN_800ea540(), 0xad < uVar4)) {
        bVar1 = false;
      }
      if (bVar1) {
        uVar9 = uVar9 | 1 << iVar8;
      }
    }
    puVar7 = puVar7 + 1;
    pcVar5 = pcVar5 + 1;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 5);
  *(char *)(iVar10 + 0x11) = (char)uVar9;
  if (DAT_803dce58 == -1) {
    iVar8 = 0;
    pbVar6 = &DAT_803dce28;
    do {
      uVar9 = FUN_80020078((&DAT_8032ae0c)[*pbVar6]);
      if (uVar9 != 0) {
        *(undefined *)(iVar10 + 0x10) = (&DAT_803dce28)[iVar8];
        break;
      }
      pbVar6 = pbVar6 + 1;
      iVar8 = iVar8 + 1;
    } while (iVar8 < 5);
  }
  else {
    *(char *)(iVar10 + 0x10) = (char)DAT_803dce58;
  }
  DAT_803de988 = 0;
  FUN_8005cf74(0);
  FUN_80009a94(0xf);
  FUN_8000a538((int *)0x8f,1);
  FLOAT_803de9ac = FLOAT_803e7290;
  uVar11 = FUN_8012e0b8('\x01');
  DAT_803de9a8 = 0xffffffff;
  FUN_80043604(0,0,1);
  FUN_80043938(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  iVar8 = FUN_80057360();
  (**(code **)(*DAT_803dd72c + 0x1c))(iVar2 + 0xc,0,0,iVar8);
  (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,1);
  DAT_803de98a = 10;
  uVar11 = FUN_800201ac(DAT_8032ae14,1);
  *(undefined2 *)(iVar10 + 6) = 0x78;
  FUN_80088a84(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  FUN_80286880();
  return;
}

