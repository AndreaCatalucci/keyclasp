package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = (*SecretDataSource)(nil)

func NewSecretDataSource() datasource.DataSource {
	return &SecretDataSource{}
}

type SecretDataSource struct{}

type SecretDataSourceModel struct {
	Name  types.String `tfsdk:"name"`
	Value types.String `tfsdk:"value"`
}

func (d *SecretDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *SecretDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads a secret from the Keyblind encrypted vault.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the secret to retrieve.",
				Required:    true,
			},
			"value": schema.StringAttribute{
				Description: "The secret value. Marked sensitive.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config SecretDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	client := NewClient("keyblind")
	value, err := client.GetSecret(config.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to read secret", err.Error())
		return
	}

	config.Value = types.StringValue(value)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}
