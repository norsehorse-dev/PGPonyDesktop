package com.pgpony.desktop

import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.layout.Placeable
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp

/**
 * D12 — a row that wraps.
 *
 * ## Why this exists
 *
 * `Row` hands out the available width in measure order and gives the last child whatever is
 * left over. With four buttons whose English labels just fit, a German or Japanese build of the
 * same screen squeezes the final button into a sliver and Compose wraps its label one character
 * per line. That was the visible defect in the key-detail dialog ("QR anzeigen…" rendered as a
 * vertical column of letters), and the same four-button-in-a-bare-Row shape appears across most
 * of the app's screens and dialogs, so a spot fix in one file would have left the bug latent
 * everywhere else. Anything measured here gets its full natural width and moves to the next
 * line instead of being compressed.
 *
 * ## Why not FlowRow
 *
 * Compose Foundation ships `FlowRow`, which does roughly this — but it is annotated
 * `@ExperimentalLayoutApi`, and using it would mean the first `@OptIn` in the project, on an API
 * that has already been reshuffled once between Compose Multiplatform releases. A `Layout` with
 * a measure lambda is the oldest stable API in Compose; it cannot be deprecated out from under a
 * release upgrade, it adds no dependency, and it lets [minItemWidth] express something FlowRow
 * has no parameter for.
 *
 * @param horizontalSpacing gap between items on the same line.
 * @param verticalSpacing gap between lines. Defaults to the same value, so a wrapped group reads
 *   as a grid rather than as two unrelated rows.
 * @param minItemWidth floor for each child's width. Useful for a group of buttons that should
 *   line up at a common width even though their labels differ in length; leave at zero to let
 *   every child size itself.
 * @param horizontalAlignment where each line sits within the available width. `End` is the right
 *   choice for the confirm/cancel pair at the foot of a dialog.
 */
@Composable
fun WrapRow(
    modifier: Modifier = Modifier,
    horizontalSpacing: Dp = Spacing.Small,
    verticalSpacing: Dp = Spacing.Small,
    minItemWidth: Dp = 0.dp,
    horizontalAlignment: Alignment.Horizontal = Alignment.Start,
    content: @Composable () -> Unit
) {
    Layout(content = content, modifier = modifier) { measurables, constraints ->
        val hGap = horizontalSpacing.roundToPx()
        val vGap = verticalSpacing.roundToPx()
        val ceiling = constraints.maxWidth
        // Each child is offered the whole width and no height bound: it reports what it actually
        // wants, and the packing below decides which line that fits on. minWidth is clamped
        // because a floor wider than the container would be an unsatisfiable constraint.
        val childConstraints = Constraints(
            minWidth = minItemWidth.roundToPx().coerceAtMost(ceiling),
            maxWidth = ceiling
        )
        val placeables = measurables.map { it.measure(childConstraints) }

        val lines = ArrayList<MutableList<Placeable>>()
        var line = ArrayList<Placeable>()
        var lineWidth = 0
        for (placeable in placeables) {
            val added = if (line.isEmpty()) placeable.width else placeable.width + hGap
            if (line.isNotEmpty() && lineWidth + added > ceiling) {
                lines.add(line)
                line = ArrayList()
                lineWidth = placeable.width
            } else {
                lineWidth += added
            }
            line.add(placeable)
        }
        if (line.isNotEmpty()) lines.add(line)

        val lineWidths = lines.map { row ->
            row.sumOf { it.width } + hGap * (row.size - 1).coerceAtLeast(0)
        }
        val lineHeights = lines.map { row -> row.maxOfOrNull { it.height } ?: 0 }
        // `coerceIn` rather than Constraints.constrainWidth/constrainHeight: those two are
        // top-level extensions in androidx.compose.ui.unit rather than members, so they need
        // their own imports, and they do exactly this. Constraints guarantees min <= max, so the
        // clamp can never be handed an inverted range.
        val totalWidth = (lineWidths.maxOrNull() ?: 0)
            .coerceIn(constraints.minWidth, constraints.maxWidth)
        val totalHeight = (lineHeights.sum() + vGap * (lines.size - 1).coerceAtLeast(0))
            .coerceIn(constraints.minHeight, constraints.maxHeight)

        layout(totalWidth, totalHeight) {
            var y = 0
            lines.forEachIndexed { index, row ->
                // Resolved as if left-to-right and then placed with `placeRelative`, which is
                // what mirrors the whole thing under an RTL layout direction. Resolving the
                // alignment against the real direction as well would mirror it twice.
                var x = horizontalAlignment.align(lineWidths[index], totalWidth, LayoutDirection.Ltr)
                val rowHeight = lineHeights[index]
                row.forEach { placeable ->
                    // Centre each item in its line so a tall child (a button beside a bare label)
                    // doesn't leave its neighbours stuck to the top edge.
                    placeable.placeRelative(x, y + (rowHeight - placeable.height) / 2)
                    x += placeable.width + hGap
                }
                y += rowHeight + vGap
            }
        }
    }
}
