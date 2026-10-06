import { reactive } from 'vue'

export const drawer = reactive<{ open: boolean; title: string; kind: string; payload: any }>({
  open: false, title: '', kind: '', payload: null,
})
export function openDrawer(title: string, kind: string, payload: any) {
  drawer.open = true; drawer.title = title; drawer.kind = kind; drawer.payload = payload
}
export function closeDrawer() { drawer.open = false }

export const modal = reactive<{ open: boolean; title: string; kind: string; payload: any }>({
  open: false, title: '', kind: '', payload: null,
})
export function openModal(title: string, kind: string, payload: any = null) {
  modal.open = true; modal.title = title; modal.kind = kind; modal.payload = payload
}
export function closeModal() { modal.open = false }
