import { useContext } from "react";
import { UiContext } from "./ui.context";

export function useUi() {
  const ctx = useContext(UiContext);
  if (!ctx) throw new Error("useUi must be used within UiProvider");
  return ctx;
}
