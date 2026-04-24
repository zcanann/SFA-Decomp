// Function: FUN_801002c0
// Entry: 801002c0
// Size: 648 bytes

/* WARNING: Removing unreachable block (ram,0x80100524) */

void FUN_801002c0(double param_1,undefined4 param_2,undefined param_3,int param_4,undefined4 param_5
                 )

{
  float fVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  double dVar3;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  fVar1 = FLOAT_803e1600;
  if (param_4 != 0) {
    param_1 = (double)*(float *)(param_4 + 8);
    fVar1 = (float)(param_1 / (double)FLOAT_803e1604);
  }
  dVar3 = (double)fVar1;
  (**(code **)(*DAT_803dca7c + 0x34))(param_1,param_2,param_3,0x15,1,0);
  (**(code **)(*DAT_803dca7c + 0x4c))(&DAT_80319344);
  (**(code **)(*DAT_803dca7c + 0x54))(param_5);
  (**(code **)(*DAT_803dca7c + 0x38))();
  (**(code **)(*DAT_803dca7c + 0x3c))
            ((double)FLOAT_803e1608,(double)FLOAT_803e160c,(double)FLOAT_803e160c,4,0x15,
             &DAT_80319318);
  (**(code **)(*DAT_803dca7c + 0x3c))
            ((double)FLOAT_803e1610,(double)FLOAT_803e1614,(double)FLOAT_803e1610,2,0x15,
             &DAT_80319318);
  (**(code **)(*DAT_803dca7c + 0x3c))
            ((double)FLOAT_803e160c,(double)FLOAT_803e1618,(double)FLOAT_803e160c,0x400000,0,0);
  (**(code **)(*DAT_803dca7c + 0x40))();
  (**(code **)(*DAT_803dca7c + 0x3c))
            ((double)FLOAT_803e161c,(double)FLOAT_803e160c,(double)FLOAT_803e160c,4,7,&DAT_803192dc)
  ;
  (**(code **)(*DAT_803dca7c + 0x40))();
  (**(code **)(*DAT_803dca7c + 0x3c))
            ((double)FLOAT_803e1620,(double)FLOAT_803e160c,(double)FLOAT_803e160c,4,7,&DAT_803192dc)
  ;
  (**(code **)(*DAT_803dca7c + 0x3c))(dVar3,(double)FLOAT_803e1624,dVar3,2,0x15,&DAT_80319318);
  (**(code **)(*DAT_803dca7c + 0x40))();
  dVar3 = (double)FLOAT_803e160c;
  (**(code **)(*DAT_803dca7c + 0x3c))(dVar3,dVar3,dVar3,4,7,&DAT_803192dc);
  (**(code **)(*DAT_803dca7c + 0x50))(param_4,&DAT_80319168,0x15,&DAT_8031923c,0x18,0x3e9,0);
  (**(code **)(*DAT_803dca7c + 0x58))();
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

