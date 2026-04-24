// Function: FUN_8003d6f8
// Entry: 8003d6f8
// Size: 648 bytes

void FUN_8003d6f8(undefined4 param_1)

{
  int iVar1;
  double dVar2;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined auStack72 [4];
  int local_44;
  int local_40;
  undefined4 local_3c;
  undefined auStack56 [48];
  
  local_3c = DAT_803de9f0;
  iVar1 = FUN_8001f4c8(param_1,0);
  if (iVar1 != 0) {
    FUN_8001db2c(iVar1,4);
    FUN_8001dc90((double)FLOAT_803dea04,(double)FLOAT_803dea34,(double)FLOAT_803dea04,iVar1);
    FUN_8001daf0(iVar1,0xff,0xff,0xff,0xff);
    FUN_8001e8f4(0);
    FUN_8001e608(2,0,0);
    local_4c = DAT_803db470;
    FUN_80259b88(2,&local_4c);
    local_50 = DAT_803db468;
    FUN_80259cf0(2,&local_50);
    FUN_8001e4a4(2,iVar1,param_1);
    FUN_8001e634();
    FUN_8001f384(iVar1);
  }
  local_54 = local_3c;
  FUN_8025bdac(0,&local_54);
  FUN_8025be8c(0,0x1c);
  FUN_8025be20(0,0xc);
  FUN_8006c4c0(&local_40,&local_44,auStack72);
  FUN_8004c2e4(*(undefined4 *)(local_40 + ((DAT_803dcc44 >> 2) + (uint)DAT_803dcc3d * local_44) * 4)
               ,0);
  FUN_80247318((double)FLOAT_803dea38,(double)FLOAT_803dea38,(double)FLOAT_803dea1c,auStack56);
  FUN_8025d160(auStack56,0x40,0);
  FUN_80257f10(1,1,4,0x3c,1,0x40);
  FUN_8025b71c(0);
  FUN_8025c0c4(0,1,0,4);
  FUN_8025ba40(0,0xf,0xf,0xf,0xe);
  FUN_8025bac0(0,7,4,5,7);
  FUN_8025bef8(0,0,0);
  FUN_8025bb44(0,0,0,0,1,0);
  FUN_8025bc04(0,0,0,3,1,0);
  FUN_8025c2a0(1);
  FUN_8025b6f0(0);
  FUN_802581e0(2);
  FUN_80258b24(2);
  local_58 = DAT_803db468;
  dVar2 = (double)FLOAT_803dea04;
  FUN_8025c2d4(dVar2,dVar2,dVar2,dVar2,0,&local_58);
  FUN_80070310(1,3,0);
  FUN_800702b8(1);
  FUN_8025c584(1,4,5,5);
  return;
}

