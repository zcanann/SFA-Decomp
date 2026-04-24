// Function: FUN_801299d4
// Entry: 801299d4
// Size: 672 bytes

void FUN_801299d4(void)

{
  int iVar1;
  byte bVar2;
  double dVar3;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  undefined4 local_24;
  undefined4 local_20;
  uint uStack28;
  double local_18;
  
  local_34 = DAT_803e1e00;
  dVar3 = (double)FUN_8000fc34();
  FLOAT_803dbaa4 = (float)dVar3;
  FUN_8000fc3c((double)FLOAT_803e2044);
  FUN_8000f458(1);
  DAT_803dd7e0 = FUN_8000fac4();
  FUN_8000facc();
  dVar3 = (double)FLOAT_803e1e3c;
  FUN_8000f510(dVar3,dVar3,dVar3);
  FUN_8000f4e0(0x8000,0,0);
  FUN_8000f564();
  FUN_8000fb00();
  dVar3 = (double)FLOAT_803e1e3c;
  uStack28 = (uint)*(ushort *)(DAT_803dccf0 + 4);
  local_20 = 0x43300000;
  local_18 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8));
  FUN_8025d300(dVar3,dVar3,(double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1e88),
               (double)(float)(local_18 - DOUBLE_803e1e88),dVar3,(double)FLOAT_803e1e68);
  for (bVar2 = 1; bVar2 < 6; bVar2 = bVar2 + 1) {
    iVar1 = (&DAT_803a9410)[bVar2];
    if (iVar1 != 0) {
      if (0x90000000 < *(uint *)(iVar1 + 0x4c)) {
        *(undefined4 *)(iVar1 + 0x4c) = 0;
      }
      FUN_8003b958(0,0,0,0,(&DAT_803a9410)[bVar2],1);
      iVar1 = FUN_8002b588((&DAT_803a9410)[bVar2]);
      *(ushort *)(iVar1 + 0x18) = *(ushort *)(iVar1 + 0x18) & 0xfff7;
      *(undefined *)((&DAT_803a9410)[bVar2] + 0x37) = 0xff;
      if (((uint)bVar2 == (int)DAT_803dba64) && (500 < DAT_803dd78c)) {
        FUN_8006c5f0((&DAT_803a9410)[bVar2],&local_24,&local_28,&local_2c,&local_30);
        local_38 = local_34;
        local_18 = (double)(longlong)(int)(FLOAT_803e20b8 * local_28);
        FUN_80076d78(local_24,local_2c,local_30,&local_38,(int)(FLOAT_803e20b8 * local_28),1);
      }
    }
  }
  for (bVar2 = 0; bVar2 < 2; bVar2 = bVar2 + 1) {
    FUN_8003b958(0,0,0,0,(&DAT_803dd868)[bVar2],1);
    iVar1 = FUN_8002b588((&DAT_803dd868)[bVar2]);
    *(ushort *)(iVar1 + 0x18) = *(ushort *)(iVar1 + 0x18) & 0xfff7;
    *(undefined *)((&DAT_803dd868)[bVar2] + 0x37) = 0xff;
  }
  FUN_8000f458(0);
  if (DAT_803dd7e0 != 0) {
    FUN_8000fad8();
  }
  FUN_8000f564();
  FUN_8000fc3c((double)FLOAT_803dbaa4);
  FUN_8000fb00();
  FUN_8000f780();
  if (((DAT_803dd778 & 0x10) != 0) && (DAT_803db424 != '\0')) {
    FUN_80019908(0xff,0xff,0xff,0xff);
    FUN_80016870(0x46e);
  }
  return;
}

