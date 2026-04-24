// Function: FUN_8010123c
// Entry: 8010123c
// Size: 276 bytes

void FUN_8010123c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined2 *puVar1;
  int iVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (DAT_803de134 == 0) {
    puVar1 = FUN_8002becc(0x18,0x1fe);
    DAT_803de134 = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar1,4,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    iVar2 = FUN_8002b660(DAT_803de134);
    FUN_80028600(iVar2,FUN_80101068);
    *(undefined *)(DAT_803de134 + 0xad) = 1;
    iVar2 = FUN_8002b660(DAT_803de134);
    FUN_80028600(iVar2,FUN_80100f2c);
    *(undefined *)(DAT_803de134 + 0xad) = 2;
    iVar2 = FUN_8002b660(DAT_803de134);
    FUN_80028600(iVar2,FUN_80100f2c);
    FUN_8001f0a4(1,0x32,0x3c,0x28);
    DAT_803de13c = FUN_8001f58c(0,'\x01');
    if (DAT_803de13c != (int *)0x0) {
      FUN_8001dbf0((int)DAT_803de13c,4);
      FUN_8001dc00((int)DAT_803de13c,1);
      FUN_8001dbf8((int)DAT_803de13c,1);
      FUN_8001dd54((double)FLOAT_803e22ac,(double)FLOAT_803e22b0,(double)FLOAT_803e22c0,DAT_803de13c
                  );
      FUN_8001dbb4((int)DAT_803de13c,0xb4,200,0xff,0xff);
    }
  }
  return;
}

