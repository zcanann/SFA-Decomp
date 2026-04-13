// Function: FUN_8009f438
// Entry: 8009f438
// Size: 288 bytes

void FUN_8009f438(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  byte bVar2;
  double dVar3;
  double dVar4;
  
  iVar1 = FUN_80008b4c(-1);
  if ((short)iVar1 != 1) {
    dVar4 = (double)FLOAT_803dc074;
    FLOAT_803ddedc = (float)((double)FLOAT_803ddedc + dVar4);
    if (FLOAT_803e0098 <= FLOAT_803ddedc) {
      FLOAT_803ddedc = FLOAT_803dffdc;
    }
    FLOAT_803ddee0 = (float)((double)FLOAT_803ddee0 + dVar4);
    if (FLOAT_803e0004 <= FLOAT_803ddee0) {
      FLOAT_803ddee0 = FLOAT_803dffdc;
    }
    FLOAT_803ddee4 = (float)((double)FLOAT_803ddee4 + dVar4);
    dVar3 = (double)FLOAT_803ddee4;
    if ((double)FLOAT_803dffd4 <= dVar3) {
      FLOAT_803ddee4 = FLOAT_803dffdc;
    }
    DAT_803dd430 = 1;
    FUN_8009bc54(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8);
    DAT_803dd430 = 0;
    bVar2 = 0x50;
    while (bVar2 != 0) {
      bVar2 = bVar2 - 1;
      (&DAT_80310528)[bVar2] = 0;
    }
    (**(code **)(*DAT_803dd708 + 0xc))(0);
    DAT_803dded4 = 1;
  }
  return;
}

