// Function: FUN_8010055c
// Entry: 8010055c
// Size: 648 bytes

/* WARNING: Removing unreachable block (ram,0x801007c0) */
/* WARNING: Removing unreachable block (ram,0x8010056c) */

void FUN_8010055c(double param_1,undefined4 param_2,undefined param_3,int param_4,undefined4 param_5
                 )

{
  float fVar1;
  double dVar2;
  
  fVar1 = FLOAT_803e2280;
  if (param_4 != 0) {
    param_1 = (double)*(float *)(param_4 + 8);
    fVar1 = (float)(param_1 / (double)FLOAT_803e2284);
  }
  dVar2 = (double)fVar1;
  (**(code **)(*DAT_803dd6fc + 0x34))(param_1,param_2,param_3,0x15,1,0);
  (**(code **)(*DAT_803dd6fc + 0x4c))(&DAT_80319f94);
  (**(code **)(*DAT_803dd6fc + 0x54))(param_5);
  (**(code **)(*DAT_803dd6fc + 0x38))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)FLOAT_803e2288,(double)FLOAT_803e228c,(double)FLOAT_803e228c,4,0x15,
             &DAT_80319f68);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)FLOAT_803e2290,(double)FLOAT_803e2294,(double)FLOAT_803e2290,2,0x15,
             &DAT_80319f68);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)FLOAT_803e228c,(double)FLOAT_803e2298,(double)FLOAT_803e228c,0x400000,0,0);
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)FLOAT_803e229c,(double)FLOAT_803e228c,(double)FLOAT_803e228c,4,7,&DAT_80319f2c)
  ;
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)FLOAT_803e22a0,(double)FLOAT_803e228c,(double)FLOAT_803e228c,4,7,&DAT_80319f2c)
  ;
  (**(code **)(*DAT_803dd6fc + 0x3c))(dVar2,(double)FLOAT_803e22a4,dVar2,2,0x15,&DAT_80319f68);
  (**(code **)(*DAT_803dd6fc + 0x40))();
  dVar2 = (double)FLOAT_803e228c;
  (**(code **)(*DAT_803dd6fc + 0x3c))(dVar2,dVar2,dVar2,4,7,&DAT_80319f2c);
  (**(code **)(*DAT_803dd6fc + 0x50))(param_4,&DAT_80319db8,0x15,&DAT_80319e8c,0x18,0x3e9,0);
  (**(code **)(*DAT_803dd6fc + 0x58))();
  return;
}

