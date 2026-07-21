#ifndef MAIN_AUDIO_MUSIC_API_H_
#define MAIN_AUDIO_MUSIC_API_H_

typedef enum MusicChannelStopMode
{
    MUSIC_CHANNEL_STOP_DEFAULT = 1,
    MUSIC_CHANNEL_STOP_FADE = 2,
} MusicChannelStopMode;

void Music_Trigger(int id, int arg);
void Music_PlayTrackByIndex(int index);
void Music_StopChannelsByPriorityGroup(int priorityGroupMask, MusicChannelStopMode mode, int fadeTime);

#endif /* MAIN_AUDIO_MUSIC_API_H_ */
