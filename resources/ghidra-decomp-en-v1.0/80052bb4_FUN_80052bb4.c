// Function: FUN_80052bb4
// Entry: 80052bb4
// Size: 524 bytes

undefined4 FUN_80052bb4(undefined4 param_1,float *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80089a58();
  iVar2 = FUN_80089a50();
  if ((iVar1 != 0) && (iVar2 != 0)) {
    FUN_8001e8f4(1);
    FUN_8001e608(0,1,0);
    FUN_8001e608(2,0,0);
    FUN_8001d994((double)*param_2,(double)FLOAT_803deb60,iVar1);
    FUN_8001da18(iVar1,0xff,0,0,0xff);
    FUN_8001e4a4(0,iVar1,param_1);
    FUN_8001d994((double)param_2[1],(double)FLOAT_803deb60,iVar1);
    FUN_8001da18(iVar1,0,0,0xff,0xff);
    FUN_8001e4a4(0,iVar1,param_1);
    FUN_8001da3c((double)FLOAT_803deb70,(double)FLOAT_803deb60,(double)FLOAT_803deb60,iVar1);
    FUN_8001e4a4(2,iVar1,param_1);
    FUN_8001e608(1,1,0);
    FUN_8001e608(3,0,0);
    FUN_8001d994((double)*param_2,(double)FLOAT_803deb60,iVar2);
    FUN_8001da18(iVar2,0xff,0,0,0xff);
    FUN_8001e4a4(1,iVar2,param_1);
    FUN_8001d994((double)param_2[1],(double)FLOAT_803deb60,iVar2);
    FUN_8001da18(iVar2,0,0,0xff,0xff);
    FUN_8001e4a4(1,iVar2,param_1);
    FUN_8001da3c((double)FLOAT_803deb74,(double)FLOAT_803deb60,(double)FLOAT_803deb60,iVar2);
    FUN_8001e4a4(3,iVar2,param_1);
    FUN_8001e634();
    FUN_8001da3c((double)FLOAT_803deb5c,(double)FLOAT_803deb60,(double)FLOAT_803deb60,iVar1);
    FUN_8001da3c((double)FLOAT_803deb5c,(double)FLOAT_803deb60,(double)FLOAT_803deb60,iVar2);
  }
  return 0;
}

