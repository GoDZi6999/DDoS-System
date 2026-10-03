import { Shell } from "@/components/shell";
import { Providers } from "@/components/providers";

export default function SocLayout({ children }: LayoutProps<"/">) {
  return (
    <Providers>
      <Shell>{children}</Shell>
    </Providers>
  );
}
