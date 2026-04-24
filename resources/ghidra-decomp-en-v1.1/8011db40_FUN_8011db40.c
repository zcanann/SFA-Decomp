// Function: FUN_8011db40
// Entry: 8011db40
// Size: 116 bytes

undefined4
FUN_8011db40(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  undefined8 uVar2;
  
  FUN_8002bac4();
  bVar1 = DAT_803dc070;
  if (3 < DAT_803dc070) {
    bVar1 = 3;
  }
  if (('\0' < DAT_803de3a8) && (DAT_803de3a8 = DAT_803de3a8 - bVar1, DAT_803de3a8 < '\x01')) {
    uVar2 = FUN_80014974(1);
    FUN_80055464(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x60,'\x01',param_11,
                 param_12,param_13,param_14,param_15,param_16);
  }
  return 0;
}

