package llm

func init() {
	RegisterProvider("deepseek", func(cfg ProviderConfig) (Client, error) {
		preset := DeepSeekProviderConfig
		preset.APIKey = cfg.APIKey
		return NewOpenAICompatibleClient(preset)
	})
}
