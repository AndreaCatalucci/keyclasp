package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = (*KeyblindProvider)(nil)

type KeyblindProvider struct{}

func New() provider.Provider {
	return &KeyblindProvider{}
}

func (p *KeyblindProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "keyblind"
}

func (p *KeyblindProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {}

func (p *KeyblindProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {}

func (p *KeyblindProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

func (p *KeyblindProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSecretResource,
	}
}
