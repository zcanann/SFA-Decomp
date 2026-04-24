// Function: FUN_80129d10
// Entry: 80129d10
// Size: 672 bytes

void FUN_80129d10(void)

{
  int iVar1;
  byte bVar2;
  double dVar3;
  double dVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  int local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  local_34 = DAT_803e2a80;
  dVar3 = FUN_8000fc54();
  FLOAT_803dc70c = (float)dVar3;
  FUN_8000fc5c((double)FLOAT_803e2cc4);
  FUN_8000f478(1);
  DAT_803de460 = FUN_8000fae4();
  FUN_8000faec();
  dVar3 = (double)FLOAT_803e2abc;
  FUN_8000f530(dVar3,dVar3,dVar3);
  FUN_8000f500(0x8000,0,0);
  FUN_8000f584();
  FUN_8000fb20();
  dVar4 = (double)FLOAT_803e2abc;
  uStack_1c = (uint)*(ushort *)(DAT_803dd970 + 4);
  local_20 = 0x43300000;
  dVar6 = (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2b08);
  local_18 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6));
  dVar7 = (double)(float)(local_18 - DOUBLE_803e2b08);
  dVar8 = (double)FLOAT_803e2ae8;
  dVar3 = dVar4;
  FUN_8025da64(dVar4,dVar4,dVar6,dVar7,dVar4,dVar8);
  for (bVar2 = 1; bVar2 < 6; bVar2 = bVar2 + 1) {
    iVar1 = (&DAT_803aa070)[bVar2];
    if (iVar1 != 0) {
      if (0x90000000 < *(uint *)(iVar1 + 0x4c)) {
        *(undefined4 *)(iVar1 + 0x4c) = 0;
      }
      FUN_8003ba50(0,0,0,0,(&DAT_803aa070)[bVar2],1);
      iVar1 = FUN_8002b660((&DAT_803aa070)[bVar2]);
      *(ushort *)(iVar1 + 0x18) = *(ushort *)(iVar1 + 0x18) & 0xfff7;
      *(undefined *)((&DAT_803aa070)[bVar2] + 0x37) = 0xff;
      if (((uint)bVar2 == (int)DAT_803dc6cc) && (500 < DAT_803de40c)) {
        FUN_8006c76c((&DAT_803aa070)[bVar2],&local_24,&local_28,&local_2c,&local_30);
        local_38 = local_34;
        local_18 = (double)(longlong)(int)(FLOAT_803e2d44 * local_28);
        FUN_80076ef4(local_24,local_2c,local_30,&local_38,(int)(FLOAT_803e2d44 * local_28),1);
      }
    }
  }
  for (bVar2 = 0; bVar2 < 2; bVar2 = bVar2 + 1) {
    FUN_8003ba50(0,0,0,0,(&DAT_803de4e8)[bVar2],1);
    iVar1 = FUN_8002b660((&DAT_803de4e8)[bVar2]);
    *(ushort *)(iVar1 + 0x18) = *(ushort *)(iVar1 + 0x18) & 0xfff7;
    *(undefined *)((&DAT_803de4e8)[bVar2] + 0x37) = 0xff;
  }
  FUN_8000f478(0);
  if (DAT_803de460 != 0) {
    FUN_8000faf8();
  }
  FUN_8000f584();
  FUN_8000fc5c((double)FLOAT_803dc70c);
  FUN_8000fb20();
  FUN_8000f7a0();
  if (((DAT_803de3f8 & 0x10) != 0) && (DAT_803dc084 != '\0')) {
    uVar5 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar5,dVar4,dVar6,dVar7,dVar3,dVar8,in_f7,in_f8,0x46e);
  }
  return;
}

