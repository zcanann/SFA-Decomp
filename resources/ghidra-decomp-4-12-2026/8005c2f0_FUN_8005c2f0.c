// Function: FUN_8005c2f0
// Entry: 8005c2f0
// Size: 1500 bytes

void FUN_8005c2f0(void)

{
  float *pfVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  uint local_288;
  float local_284;
  float local_280;
  undefined4 local_27c;
  undefined auStack_278 [616];
  
  DAT_803ddab4 = FUN_8009461c(&local_280,&local_284);
  if (DAT_803ddab4 != 0) {
    DAT_80382c68 = FLOAT_803df890;
    DAT_80382c6c = FLOAT_803df84c;
    DAT_80382c70 = FLOAT_803df84c;
    DAT_80382c74 = FLOAT_803df890 * FLOAT_803dda58 + local_280;
    DAT_80382c78 = FLOAT_803df84c;
    DAT_80382c7c = FLOAT_803df84c;
    DAT_80382c80 = FLOAT_803df890;
    DAT_80382c84 = FLOAT_803df890 * FLOAT_803dda5c + local_284;
    DAT_80382c88 = FLOAT_803df84c;
    DAT_80382c8c = FLOAT_803df84c;
    DAT_80382c90 = FLOAT_803df84c;
    DAT_80382c94 = FLOAT_803df85c;
    pfVar1 = (float *)FUN_8000f578();
    FUN_80247618(&DAT_80382c68,pfVar1,&DAT_80382c68);
  }
  FUN_8005a5d8((undefined4 *)&DAT_80382e84);
  FUN_80062a10();
  FUN_80062984();
  DAT_803ddb2e = 1;
  DAT_803ddb2c = 0;
  DAT_803dda86 = 0;
  FUN_8006c924();
  DAT_803ddab0 = 0;
  FUN_8005b7d0();
  FUN_80053078();
  FUN_8012a0f0();
  FUN_80258c24();
  FUN_8000f11c();
  FUN_8000f584();
  FUN_8000fb20();
  iVar2 = 0;
  if (((DAT_803dda68 & 0x40) != 0) && ((DAT_803dda68 & 0x80000) == 0)) {
    iVar2 = 1;
  }
  if ((DAT_803dda68 & 0x40000) == 0) {
    (**(code **)(*DAT_803dd6d8 + 0x10))(0,0,0,0,iVar2);
    (**(code **)(*DAT_803dd6e4 + 0x10))(0,0,0,0);
    FUN_80093d6c();
  }
  else {
    (**(code **)(*DAT_803dd6d8 + 0x38))(0,0);
    if (iVar2 != 0) {
      FUN_80093d6c();
    }
    (**(code **)(*DAT_803dd6d8 + 0x10))(0,0,0,0,iVar2);
    if ((DAT_803dda68 & 0x10) != 0) {
      (**(code **)(*DAT_803dd6e4 + 0x10))(0,0,0,0);
    }
  }
  if (DAT_803dda85 != '\0') {
    FUN_80071050(DAT_803dda85);
  }
  FUN_8008fd80();
  (**(code **)(*DAT_803dd6dc + 0x10))(0);
  DAT_803dda70 = 0;
  FUN_80089b54(0,(undefined *)&local_27c,(undefined *)((int)&local_27c + 1),
               (undefined *)((int)&local_27c + 2));
  FUN_8025a608(0,1,0,1,0,0,2);
  FUN_8025a608(2,0,0,1,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  local_288 = local_27c;
  FUN_8025a2ec(0,&local_288);
  FUN_8025a5bc(1);
  FUN_8005be04();
  FUN_8003fd58();
  FUN_8005bc3c();
  uVar3 = FUN_8000e640();
  if (((uVar3 & 0xff) != 0) || (DAT_803dda77 != '\0')) {
    FUN_8007ae8c((double)FLOAT_803dc28c);
  }
  iVar2 = FUN_80020800();
  if (iVar2 == 0) {
    FUN_8006c9ac();
  }
  if (DAT_803dda74 != '\0') {
    FUN_8007b198((double)FLOAT_803ddad0,(double)FLOAT_803ddacc,(double)FLOAT_803ddac8,DAT_803dda75,
                 DAT_803dda7b);
  }
  if (DAT_803dda7c != 0) {
    FUN_8007a898(DAT_803dda7c & 0xff);
  }
  piVar5 = &DAT_80382e34;
  for (iVar2 = 0; iVar2 < DAT_803dda70; iVar2 = iVar2 + 1) {
    (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,1,*piVar5);
    FUN_8003ba50(0,0,0,0,*piVar5,1);
    piVar5 = piVar5 + 1;
  }
  FUN_8009ef70();
  FUN_8005be04();
  FUN_8005be04();
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  iVar2 = DAT_803ddab0;
  (&DAT_8037ed28)[DAT_803ddab0 * 4] = 0x78000000;
  (&DAT_8037ed2c)[iVar2 * 4] = 8;
  DAT_803ddab0 = DAT_803ddab0 + 1;
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  iVar2 = DAT_803ddab0;
  (&DAT_8037ed28)[DAT_803ddab0 * 4] = 0x50000000;
  (&DAT_8037ed2c)[iVar2 * 4] = 9;
  DAT_803ddab0 = DAT_803ddab0 + 1;
  FUN_8005dcb4();
  (**(code **)(*DAT_803dd6fc + 0x30))(auStack_278);
  (**(code **)(*DAT_803dd6fc + 0x1c))(0,0,0,0,0);
  iVar2 = FUN_8002bac4();
  if (iVar2 != 0) {
    iVar6 = iVar2;
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar2 + 0xeb); iVar4 = iVar4 + 1) {
      if (*(short *)(*(int *)(iVar6 + 200) + 0x44) == 0x2d) {
        (**(code **)(**(int **)(*(int *)(iVar6 + 200) + 0x68) + 0x2c))();
      }
      iVar6 = iVar6 + 4;
    }
  }
  FUN_8016e0a0();
  (**(code **)(*DAT_803dd6e0 + 0x14))(0);
  if (DAT_803dda76 != '\0') {
    FUN_8006c9ac();
    FUN_8007242c((double)FLOAT_803ddac4,(double)FLOAT_803ddabc,(float *)&DAT_80382e28,&DAT_803ddac0)
    ;
  }
  FUN_8005ffa4();
  (**(code **)(*DAT_803dd6d0 + 0x58))(0,0,0,0);
  if (DAT_803dda78 == '\0') {
    if (DAT_803dda79 != '\0') {
      FUN_80071978();
    }
  }
  else {
    FUN_80071ed0(&DAT_803dc290);
  }
  if (DAT_803dda7a != '\0') {
    FUN_80079be0((double)FLOAT_803df894,(double)FLOAT_803df898,0x40,'\0');
  }
  if (DAT_803ddab8 == 1) {
    FUN_80071ed0(&DAT_803dc290);
  }
  FUN_80062a54(0);
  return;
}

