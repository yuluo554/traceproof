/**
 * hazard-triage · 视频关键帧选择（源仓 `extract/video.py` 的纯函数）。
 *
 * 器官不打开视频、不抽帧、不落盘：`subject.video.total_frames` 是输入事实，
 * 这里只复刻「帧号均匀抽样（含首帧、升序去重、不越界）」的确定性选择。
 */

export function selectKeyframes(totalFrames: number, maxFrames = 8): number[] {
  const total = Math.trunc(Number(totalFrames))
  const cap = Math.max(1, Math.trunc(Number(maxFrames)))
  if (!Number.isFinite(total) || total <= 0) return []
  if (total <= cap) return Array.from({ length: total }, (_, index) => index)
  const step = total / cap
  const frames = new Set<number>()
  for (let index = 0; index < cap; index += 1) {
    frames.add(Math.min(Math.trunc(index * step), total - 1))
  }
  return [...frames].sort((left, right) => left - right)
}