// Function: FUN_8012845c
// Entry: 8012845c
// Size: 848 bytes

void FUN_8012845c(undefined4 param_1,undefined param_2)

{
  char cVar1;
  ushort uVar2;
  undefined2 uVar3;
  byte *pbVar4;
  char cVar5;
  int iVar6;
  
  iVar6 = (int)(short)(200 - DAT_803de3dc);
  FUN_8011f088((double)FLOAT_803e2d60,(double)FLOAT_803e2d64,DAT_803a9648,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  FUN_8011ee20((double)FLOAT_803e2c28,(double)FLOAT_803e2d64,DAT_803a9648,iVar6,param_2,
               (int)FLOAT_803e2bb4,0x1c,0x1e,1);
  FUN_8011ee20((double)FLOAT_803e2d60,(double)FLOAT_803e2d68,DAT_803a9648,iVar6,param_2,
               (int)FLOAT_803e2bb4,0x1c,0x1e,2);
  FUN_8011ee20((double)FLOAT_803e2c28,(double)FLOAT_803e2d68,DAT_803a9648,iVar6,param_2,
               (int)FLOAT_803e2bb4,0x1c,0x1e,3);
  FUN_8011ee20((double)FLOAT_803e2d6c,(double)FLOAT_803e2d70,DAT_803a964c,iVar6,param_2,
               (int)FLOAT_803e2bb4,8,0x20,0);
  FUN_8011ee20((double)FLOAT_803e2d6c,(double)FLOAT_803e2d74,DAT_803a964c,iVar6,param_2,
               (int)FLOAT_803e2bb4,8,0x20,0);
  FUN_8011f088((double)FLOAT_803e2d78,(double)FLOAT_803e2c50,DAT_803a9650,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  FUN_8011f088((double)FLOAT_803e2d7c,(double)FLOAT_803e2d80,DAT_803a9650,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  FUN_8011f088((double)FLOAT_803e2d84,(double)FLOAT_803e2d80,DAT_803a9650,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  FUN_8011f088((double)FLOAT_803e2d7c,(double)FLOAT_803e2d88,DAT_803a9650,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  FUN_8011f088((double)FLOAT_803e2d84,(double)FLOAT_803e2d88,DAT_803a9650,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  FUN_8011f088((double)FLOAT_803e2d78,(double)FLOAT_803e2d8c,DAT_803a9650,iVar6,param_2,
               (int)FLOAT_803e2bb4,0);
  uVar2 = FUN_800ea540();
  if (uVar2 < 0xb4) {
    if (uVar2 < 0xb1) {
      if (uVar2 < 0x8b) {
        if (uVar2 < 0x72) {
          if (uVar2 < 0x49) {
            if (uVar2 < 9) {
              cVar1 = '\0';
            }
            else {
              cVar1 = '\x01';
            }
          }
          else {
            cVar1 = '\x02';
          }
        }
        else {
          cVar1 = '\x03';
        }
      }
      else {
        cVar1 = '\x04';
      }
    }
    else {
      cVar1 = '\x05';
    }
  }
  else {
    cVar1 = '\x06';
  }
  pbVar4 = &DAT_803dc704;
  for (cVar5 = '\0'; cVar5 < '\x06'; cVar5 = cVar5 + '\x01') {
    uVar3 = 0x11;
    if (cVar1 <= cVar5) {
      uVar3 = 0xffff;
    }
    *(undefined2 *)(&DAT_8031c7e0 + (uint)*pbVar4 * 0x20) = uVar3;
    pbVar4 = pbVar4 + 1;
  }
  return;
}

