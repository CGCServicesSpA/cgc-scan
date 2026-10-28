class CgcScan < Formula
  desc "Análisis de seguridad local con cobertura honesta para agentes y CI"
  homepage "https://github.com/CGCServicesSpA/cgc-scan"
  version "0.1.0-rc.2"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_darwin_arm64.tar.gz"
      sha256 "3deedcbd45216a9f2750613530b7f9b450e3daff758927a950761d35b1daf8af"
    else
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_darwin_amd64.tar.gz"
      sha256 "2abe8f391e5ec59db4ccdb657a3661125bc2fedd492a8b25b801bad46266e0dd"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_linux_arm64.tar.gz"
      sha256 "58dda6ae59b446a132321042313516a76088b6e94b062d5a5ec88cf8d61e379e"
    else
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_linux_amd64.tar.gz"
      sha256 "cb544fe76e570f143162f731c8aa13a2bd9beb5fd5e6a6c0b35eda76c83cca24"
    end
  end

  def install
    bin.install "cgc-scan"
  end

  test do
    assert_match "esquema 1.0.0", shell_output("#{bin}/cgc-scan --version")
  end
end
