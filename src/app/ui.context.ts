import { createContext } from "react";

export type UiContextValue = {
  isNavOpen: boolean;
  openNav: () => void;
  closeNav: () => void;
  toggleNav: () => void;
};

export const UiContext = createContext<UiContextValue | null>(null);
