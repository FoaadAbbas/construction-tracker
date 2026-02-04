import { useMemo, useState, type ReactNode } from "react";
import { UiContext } from "./ui.context";

export function UiProvider({ children }: { children: ReactNode }) {
  const [isNavOpen, setIsNavOpen] = useState(false);

  const value = useMemo(
    () => ({
      isNavOpen,
      openNav: () => setIsNavOpen(true),
      closeNav: () => setIsNavOpen(false),
      toggleNav: () => setIsNavOpen((v) => !v),
    }),
    [isNavOpen]
  );

  return <UiContext.Provider value={value}>{children}</UiContext.Provider>;
}
