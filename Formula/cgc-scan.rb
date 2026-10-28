class CgcScan < Formula
  desc "Análisis de seguridad local con cobertura honesta para agentes y CI"
  homepage "https://github.com/CGCServicesSpA/cgc-scan"
  version "0.1.0-rc.1"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_darwin_arm64.tar.gz"
      sha256 "c52abd0eab40a28156000e69c5b5a8f975aa6d3a3ba8bf8babaf73b7bdd8109b"
    else
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_darwin_amd64.tar.gz"
      sha256 "0c261f882a28f0030207ecda501f6dfb793abec2d2d70f0c1681dfcf8d0fa267"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_linux_arm64.tar.gz"
      sha256 "d58f5fbe5b76f42272c1c3393d799212eb341277d2821803a7a11dadfe1b523c"
    else
      url "https://github.com/CGCServicesSpA/cgc-scan/releases/download/v#{version}/cgc-scan_#{version}_linux_amd64.tar.gz"
      sha256 "6e7e6a7d902d3f46ca8a2c494339507a8ebdc4cced9e143630f381e1ccc3de21"
    end
  end

  def install
    bin.install "cgc-scan"
  end

  test do
    assert_match "esquema 1.0.0", shell_output("#{bin}/cgc-scan --version")
  end
end
