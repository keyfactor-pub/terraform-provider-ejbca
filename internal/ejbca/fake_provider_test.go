package ejbca

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type NoopDataSourceProvider interface {
	provider.Provider
	GetDataSourceConfig() string
}

func NewFakeProvider(inner *Provider) provider.Provider {
	return &FakeProvider{
		inner: inner,
	}
}

func NewFakeProviderWithNoopDataSource(inner *Provider) NoopDataSourceProvider {
	return &FakeProvider{
		inner:      inner,
		dataSource: &FakeDataSource{typeName: "ejbca_fake"},
	}
}

type FakeProvider struct {
	inner      *Provider
	dataSource *FakeDataSource
}

// Configure implements provider.Provider.
func (m *FakeProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	m.inner.Configure(ctx, req, resp)
}

// DataSources implements provider.Provider.
func (m *FakeProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	if m.dataSource == nil {
		return m.inner.DataSources(ctx)
	}

	// If the FakeProvider has override datasources, build functions that return them.
	dss := []func() datasource.DataSource{
		func() datasource.DataSource {
			return m.dataSource
		},
	}
	return dss
}

// Metadata implements provider.Provider.
func (m *FakeProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	m.inner.Metadata(ctx, req, resp)
}

// Resources implements provider.Provider.
func (m *FakeProvider) Resources(ctx context.Context) []func() resource.Resource {
	return m.inner.Resources(ctx)
}

// Schema implements provider.Provider.
func (m *FakeProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	m.inner.Schema(ctx, req, resp)
}

type FakeDataSource struct {
	typeName string
}

type FakeDataSourceModel struct {
	ID types.String `tfsdk:"id"`
}

func (m *FakeProvider) GetDataSourceConfig() string {
	if m.dataSource == nil {
		return ""
	}
	return fmt.Sprintf(`
    data "%s" "test" {}
    `, m.dataSource.typeName)
}

// Metadata implements datasource.DataSource.
func (f *FakeDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = f.typeName
}

// Read implements datasource.DataSource.
func (f *FakeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state FakeDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.ID = types.StringValue("fake-id-1234")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Schema implements datasource.DataSource.
func (f *FakeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			// Computed attributes
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Fake ID",
			},
		},
	}
}
