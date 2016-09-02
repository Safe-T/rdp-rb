
require_relative '../lib/rdp'

RSpec.describe RDP::NegReqAction do
  describe 'Class Existed' do
    it 'Check if RDP::NegReqAction exists' do
      expect(RDP::NegReqAction).to be_a Class
    end

    it 'Check if RDP::TPKTHeaderParser exists' do
      expect(RDP::TPKTHeaderParser).to be_a Class
    end

    it 'Check if RDP::X224Header exists' do
      expect(RDP::X224Header).to be_a Class
    end

    it 'Check if RDP::NegReqHeader exists' do
      expect(RDP::NegReqHeader).to be_a Class
    end

    it 'Check if RDP::NegCorrelationInfoHeader exists' do
      expect(RDP::NegCorrelationInfoHeader).to be_a Class
    end

    it 'Check if RDP::RDPException exists' do
      expect(RDP::RDPException).to be_a Class
    end

    it 'Check if RDP::NegRspHeader exists' do
      expect(RDP::NegRspHeader).to be_a Class
    end

    it 'Check if RDP::NegFailureHeader exists' do
      expect(RDP::NegFailureHeader).to be_a Class
    end

  end
end