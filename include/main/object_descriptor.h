#ifndef MAIN_OBJECT_DESCRIPTOR_H_
#define MAIN_OBJECT_DESCRIPTOR_H_

#include "ghidra_import.h"

typedef void (*ObjectDescriptorCallback)(void);
typedef int (*ObjectDescriptorExtraSizeCallback)(void);

typedef struct ObjectDescriptor {
  u32 reserved0;
  u32 reserved1;
  u32 reserved2;
  u32 slotCountAndFlags;
  ObjectDescriptorCallback initialise;
  ObjectDescriptorCallback release;
  ObjectDescriptorCallback slot02;
  ObjectDescriptorCallback init;
  ObjectDescriptorCallback update;
  ObjectDescriptorCallback hitDetect;
  ObjectDescriptorCallback render;
  ObjectDescriptorCallback free;
  ObjectDescriptorCallback slot08;
  ObjectDescriptorExtraSizeCallback getExtraSize;
} ObjectDescriptor;

#define OBJECT_DESCRIPTOR_FLAGS_10_SLOTS 0x00090000

#endif /* MAIN_OBJECT_DESCRIPTOR_H_ */
