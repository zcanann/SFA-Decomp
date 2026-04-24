// Function: FUN_80052d30
// Entry: 80052d30
// Size: 524 bytes

undefined4 FUN_80052d30(int param_1,float *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80089ce4();
  iVar2 = FUN_80089cdc();
  if ((iVar1 != 0) && (iVar2 != 0)) {
    FUN_8001e9b8(1);
    FUN_8001e6cc(0,1,0);
    FUN_8001e6cc(2,0,0);
    FUN_8001da58((double)*param_2,(double)FLOAT_803df7e0,iVar1);
    FUN_8001dadc(iVar1,0xff,0,0,0xff);
    FUN_8001e568(0,iVar1,param_1);
    FUN_8001da58((double)param_2[1],(double)FLOAT_803df7e0,iVar1);
    FUN_8001dadc(iVar1,0,0,0xff,0xff);
    FUN_8001e568(0,iVar1,param_1);
    FUN_8001db00((double)FLOAT_803df7f0,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar1);
    FUN_8001e568(2,iVar1,param_1);
    FUN_8001e6cc(1,1,0);
    FUN_8001e6cc(3,0,0);
    FUN_8001da58((double)*param_2,(double)FLOAT_803df7e0,iVar2);
    FUN_8001dadc(iVar2,0xff,0,0,0xff);
    FUN_8001e568(1,iVar2,param_1);
    FUN_8001da58((double)param_2[1],(double)FLOAT_803df7e0,iVar2);
    FUN_8001dadc(iVar2,0,0,0xff,0xff);
    FUN_8001e568(1,iVar2,param_1);
    FUN_8001db00((double)FLOAT_803df7f4,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar2);
    FUN_8001e568(3,iVar2,param_1);
    FUN_8001e6f8();
    FUN_8001db00((double)FLOAT_803df7dc,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar1);
    FUN_8001db00((double)FLOAT_803df7dc,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar2);
  }
  return 0;
}

